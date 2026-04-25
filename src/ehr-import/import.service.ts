import { Injectable, Logger, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as crypto from 'crypto';
import { ImportJob, ImportJobStatus, ImportFormat } from './entities/import-job.entity';
import { ImportError } from './entities/import-error.entity';
import { Record as RecordEntity } from '../records/entities/record.entity';
import { Hl7Parser } from './parsers/hl7.parser';
import { CcdParser } from './parsers/ccd.parser';
import { CsvParser, CsvColumnMap } from './parsers/csv.parser';
import { ParsedRecord } from './parsers/parsed-record.interface';
import { IpfsService } from '../records/services/ipfs.service';
import { StellarService } from '../records/services/stellar.service';

const STELLAR_BATCH_SIZE = 50;

export interface JobStatus {
  jobId: string;
  status: ImportJobStatus;
  total: number;
  processed: number;
  succeeded: number;
  failed: number;
  errors: Array<{ rowIndex: number; errorMessage: string }>;
}

@Injectable()
export class ImportService {
  private readonly logger = new Logger(ImportService.name);

  constructor(
    @InjectRepository(ImportJob)
    private readonly jobRepo: Repository<ImportJob>,
    @InjectRepository(ImportError)
    private readonly errorRepo: Repository<ImportError>,
    @InjectRepository(RecordEntity)
    private readonly recordRepo: Repository<RecordEntity>,
    private readonly hl7Parser: Hl7Parser,
    private readonly ccdParser: CcdParser,
    private readonly csvParser: CsvParser,
    private readonly ipfs: IpfsService,
    private readonly stellar: StellarService,
  ) {}

  /** Detect format, create job, run pipeline (or dry-run). Returns jobId. */
  async enqueue(
    fileBuffer: Buffer,
    originalName: string,
    dryRun = false,
    columnMap?: CsvColumnMap,
  ): Promise<{ jobId: string; importBatchId: string }> {
    const format = this._detectFormat(originalName, fileBuffer);
    const importBatchId = crypto
      .createHash('sha256')
      .update(fileBuffer)
      .digest('hex');

    // Idempotency: skip if already processed
    const existing = await this.jobRepo.findOne({ where: { importBatchId } });
    if (existing && existing.status === ImportJobStatus.COMPLETED) {
      return { jobId: existing.id, importBatchId };
    }

    const job = await this.jobRepo.save(
      this.jobRepo.create({ importBatchId, format, dryRun }),
    );

    // Run asynchronously — don't await so the HTTP response returns immediately
    this._runPipeline(job, fileBuffer, columnMap).catch((err) =>
      this.logger.error(`Pipeline error for job ${job.id}: ${err.message}`),
    );

    return { jobId: job.id, importBatchId };
  }

  async getStatus(jobId: string): Promise<JobStatus> {
    const job = await this.jobRepo.findOneOrFail({ where: { id: jobId } });
    const errors = await this.errorRepo.find({ where: { jobId } });
    return {
      jobId: job.id,
      status: job.status,
      total: job.total,
      processed: job.processed,
      succeeded: job.succeeded,
      failed: job.failed,
      errors: errors.map((e) => ({ rowIndex: e.rowIndex, errorMessage: e.errorMessage })),
    };
  }

  /** Returns CSV text of all failed rows for a job. */
  async exportErrors(jobId: string): Promise<string> {
    const errors = await this.errorRepo.find({ where: { jobId } });
    const header = 'rowIndex,errorMessage,sourceRow';
    const rows = errors.map(
      (e) =>
        `${e.rowIndex},"${e.errorMessage.replace(/"/g, '""')}","${e.sourceRow.replace(/"/g, '""')}"`,
    );
    return [header, ...rows].join('\n');
  }

  // ── Pipeline ───────────────────────────────────────────────────────────────

  private async _runPipeline(
    job: ImportJob,
    buffer: Buffer,
    columnMap?: CsvColumnMap,
  ): Promise<void> {
    await this.jobRepo.update(job.id, { status: ImportJobStatus.PROCESSING });

    let records: ParsedRecord[];
    try {
      records = await this._parse(job.format, buffer, columnMap);
    } catch (err) {
      await this.jobRepo.update(job.id, { status: ImportJobStatus.FAILED });
      throw err;
    }

    await this.jobRepo.update(job.id, { total: records.length });

    let succeeded = 0;
    let failed = 0;

    // Process in Stellar batch windows
    for (let i = 0; i < records.length; i += STELLAR_BATCH_SIZE) {
      const batch = records.slice(i, i + STELLAR_BATCH_SIZE);
      const anchored: Array<{ record: ParsedRecord; cid: string; idx: number }> = [];

      for (let j = 0; j < batch.length; j++) {
        const rec = batch[j];
        const globalIdx = i + j;
        try {
          if (!job.dryRun) {
            const cid = await this.ipfs.upload(Buffer.from(rec.rawPayload));
            anchored.push({ record: rec, cid, idx: globalIdx });
          } else {
            succeeded++;
          }
        } catch (err: any) {
          failed++;
          await this._logError(job.id, globalIdx, rec.rawPayload, err);
        }
      }

      if (!job.dryRun && anchored.length > 0) {
        // One Stellar tx per batch
        let stellarTxHash: string | null = null;
        try {
          // Anchor the first CID on behalf of the batch (batch anchor)
          stellarTxHash = await this.stellar.anchorCid(
            anchored[0].record.patientId,
            anchored.map((a) => a.cid).join(','),
          );
        } catch (err: any) {
          // If Stellar fails, mark all in batch as failed
          for (const a of anchored) {
            failed++;
            await this._logError(job.id, a.idx, a.record.rawPayload, err);
          }
          await this.jobRepo.update(job.id, {
            processed: i + batch.length,
            succeeded,
            failed,
          });
          continue;
        }

        for (const a of anchored) {
          try {
            await this.recordRepo.save(
              this.recordRepo.create({
                patientId: a.record.patientId,
                cid: a.cid,
                stellarTxHash: stellarTxHash ?? undefined,
                recordType: a.record.recordType,
                description: a.record.description,
              }),
            );
            succeeded++;
          } catch (err: any) {
            failed++;
            await this._logError(job.id, a.idx, a.record.rawPayload, err);
          }
        }
      }

      await this.jobRepo.update(job.id, {
        processed: i + batch.length,
        succeeded,
        failed,
      });
    }

    await this.jobRepo.update(job.id, {
      status: ImportJobStatus.COMPLETED,
      succeeded,
      failed,
    });
  }

  private async _parse(
    format: ImportFormat,
    buffer: Buffer,
    columnMap?: CsvColumnMap,
  ): Promise<ParsedRecord[]> {
    const text = buffer.toString('utf-8');
    switch (format) {
      case ImportFormat.HL7:
        return this.hl7Parser.parse(text);
      case ImportFormat.CCD:
        return this.ccdParser.parse(text);
      case ImportFormat.CSV:
        return this.csvParser.parse(text, columnMap);
      default:
        throw new BadRequestException(`Unsupported format: ${format}`);
    }
  }

  private _detectFormat(filename: string, buffer: Buffer): ImportFormat {
    const ext = filename.split('.').pop()?.toLowerCase();
    if (ext === 'csv') return ImportFormat.CSV;
    if (ext === 'xml' || ext === 'ccd' || ext === 'ccda') return ImportFormat.CCD;
    if (ext === 'hl7' || ext === 'txt') return ImportFormat.HL7;
    // Sniff content
    const head = buffer.slice(0, 10).toString();
    if (head.startsWith('MSH|')) return ImportFormat.HL7;
    if (head.trimStart().startsWith('<')) return ImportFormat.CCD;
    return ImportFormat.CSV;
  }

  private async _logError(
    jobId: string,
    rowIndex: number,
    sourceRow: string,
    err: Error,
  ): Promise<void> {
    await this.errorRepo.save(
      this.errorRepo.create({
        jobId,
        rowIndex,
        sourceRow: sourceRow.slice(0, 2000),
        errorMessage: err.message,
        stack: err.stack?.slice(0, 2000) ?? null,
      }),
    );
  }
}
