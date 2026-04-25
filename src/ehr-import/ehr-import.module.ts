import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { MulterModule } from '@nestjs/platform-express';
import { ImportJob } from './entities/import-job.entity';
import { ImportError } from './entities/import-error.entity';
import { Record } from '../records/entities/record.entity';
import { ImportService } from './import.service';
import { ImportController } from './import.controller';
import { Hl7Parser } from './parsers/hl7.parser';
import { CcdParser } from './parsers/ccd.parser';
import { CsvParser } from './parsers/csv.parser';
import { IpfsService } from '../records/services/ipfs.service';
import { StellarService } from '../records/services/stellar.service';
import { TracingService } from '../common/services/tracing.service';

@Module({
  imports: [
    TypeOrmModule.forFeature([ImportJob, ImportError, Record]),
    MulterModule.register({ limits: { fileSize: 50 * 1024 * 1024 } }), // 50 MB
  ],
  controllers: [ImportController],
  providers: [
    ImportService, Hl7Parser, CcdParser, CsvParser,
    IpfsService, StellarService, TracingService,
  ],
  exports: [ImportService],
})
export class EhrImportModule {}
