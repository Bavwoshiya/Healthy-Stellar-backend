import {
  Injectable,
  BadRequestException,
  NotFoundException,
  InternalServerErrorException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { RecordAttachment, AttachmentMimeType } from '../entities/record-attachment.entity';
import { Record } from '../entities/record.entity';
import { EncryptionService } from '../../encryption/services/encryption.service';
import { IpfsService } from './ipfs.service';
import { AuditLogService } from '../../common/services/audit-log.service';

// Allowed MIME types as per requirements
const ALLOWED_MIME_TYPES = [
  AttachmentMimeType.PDF,
  AttachmentMimeType.JPEG,
  AttachmentMimeType.PNG,
  AttachmentMimeType.DICOM,
];

const MAX_FILE_SIZE = 50 * 1024 * 1024; // 50MB

@Injectable()
export class RecordAttachmentUploadService {
  constructor(
    @InjectRepository(RecordAttachment)
    private attachmentRepository: Repository<RecordAttachment>,
    @InjectRepository(Record)
    private recordRepository: Repository<Record>,
    private encryptionService: EncryptionService,
    private ipfsService: IpfsService,
    private auditLogService: AuditLogService,
  ) {}

  /**
   * Upload and encrypt a file attachment for a record
   *
   * Process:
   * 1. Validate record exists
   * 2. Validate file (MIME type, size)
   * 3. Encrypt file using patient's KEK
   * 4. Upload encrypted bytes to IPFS
   * 5. Save attachment metadata to database
   * 6. Log audit entry
   *
   * @param recordId - UUID of the record
   * @param file - Express file object with buffer, originalname, mimetype
   * @param uploadedBy - User ID performing the upload
   * @returns Attachment metadata (id, cid, fileSize)
   */
  async uploadAttachment(
    recordId: string,
    file: Express.Multer.File,
    uploadedBy: string,
  ): Promise<{ attachmentId: string; cid: string; fileSize: number }> {
    // Step 1: Validate record exists
    const record = await this.recordRepository.findOne({
      where: { id: recordId, isDeleted: false },
    });

    if (!record) {
      throw new NotFoundException(`Record with ID ${recordId} not found`);
    }

    // Step 2: Validate file
    this.validateFile(file);

    // Step 3: Encrypt file using patient's KEK
    let encryptedRecord;
    try {
      encryptedRecord = await this.encryptionService.encryptRecord(
        file.buffer,
        record.patientId,
      );
    } catch (error) {
      throw new InternalServerErrorException(
        `Failed to encrypt attachment: ${error.message}`,
      );
    }

    // Build the encrypted envelope (same format as records)
    const encryptedEnvelope = this.buildEncryptedEnvelope(encryptedRecord);

    // Step 4: Upload encrypted bytes to IPFS
    let cid: string;
    try {
      cid = await this.ipfsService.upload(encryptedEnvelope);
    } catch (error) {
      throw new InternalServerErrorException(
        `Failed to upload to IPFS: ${error.message}`,
      );
    }

    // Step 5: Save attachment metadata to database
    const attachment = this.attachmentRepository.create({
      recordId,
      originalFilename: file.originalname,
      mimeType: file.mimetype as AttachmentMimeType,
      cid,
      fileSize: file.size,
      uploadedBy,
      isDeleted: false,
    });

    const savedAttachment = await this.attachmentRepository.save(attachment);

    // Step 6: Log audit entry
    await this.auditLogService.log({
      userId: uploadedBy,
      action: 'ATTACHMENT_UPLOAD',
      resourceType: 'RecordAttachment',
      resourceId: savedAttachment.id,
      metadata: {
        recordId,
        filename: file.originalname,
        mimeType: file.mimetype,
        fileSize: file.size,
        cid,
      },
    });

    return {
      attachmentId: savedAttachment.id,
      cid: savedAttachment.cid,
      fileSize: savedAttachment.fileSize,
    };
  }

  /**
   * Get attachment by ID with access control
   */
  async getAttachment(attachmentId: string): Promise<RecordAttachment> {
    const attachment = await this.attachmentRepository.findOne({
      where: { id: attachmentId, isDeleted: false },
      relations: ['record'],
    });

    if (!attachment) {
      throw new NotFoundException(`Attachment with ID ${attachmentId} not found`);
    }

    return attachment;
  }

  /**
   * List attachments for a record
   */
  async listAttachments(
    recordId: string,
  ): Promise<RecordAttachment[]> {
    return this.attachmentRepository.find({
      where: { recordId, isDeleted: false },
      order: { uploadedAt: 'DESC' },
    });
  }

  /**
   * Soft delete an attachment
   */
  async deleteAttachment(attachmentId: string, deletedBy: string): Promise<void> {
    const attachment = await this.attachmentRepository.findOne({
      where: { id: attachmentId },
    });

    if (!attachment) {
      throw new NotFoundException(`Attachment with ID ${attachmentId} not found`);
    }

    attachment.isDeleted = true;
    await this.attachmentRepository.save(attachment);

    // Log audit entry
    await this.auditLogService.log({
      userId: deletedBy,
      action: 'ATTACHMENT_DELETE',
      resourceType: 'RecordAttachment',
      resourceId: attachmentId,
      metadata: {
        recordId: attachment.recordId,
        originalFilename: attachment.originalFilename,
      },
    });
  }

  /**
   * Validate file before encryption
   */
  private validateFile(file: Express.Multer.File): void {
    if (!file) {
      throw new BadRequestException('No file provided');
    }

    // Check MIME type
    if (!ALLOWED_MIME_TYPES.includes(file.mimetype as AttachmentMimeType)) {
      throw new BadRequestException(
        `Invalid MIME type: ${file.mimetype}. Allowed: ${ALLOWED_MIME_TYPES.join(', ')}`,
      );
    }

    // Check file size
    if (file.size > MAX_FILE_SIZE) {
      throw new BadRequestException(
        `File size ${file.size} exceeds maximum of ${MAX_FILE_SIZE} bytes`,
      );
    }

    if (file.size === 0) {
      throw new BadRequestException('File is empty');
    }
  }

  /**
   * Build encrypted envelope from encryption result
   * Format: iv(12) | authTag(16) | dekLen(4) | encryptedDek(N) | dekVersion(2) | ciphertext(rest)
   */
  private buildEncryptedEnvelope(encryptedRecord: any): Buffer {
    const iv = encryptedRecord.iv;
    const authTag = encryptedRecord.authTag;
    const encryptedDek = encryptedRecord.encryptedDek;
    const dekVersion = encryptedRecord.dekVersion;
    const ciphertext = encryptedRecord.ciphertext;

    // Calculate total size
    const dekLen = Buffer.allocUnsafe(4);
    dekLen.writeUInt32BE(encryptedDek.length, 0);

    const dekVersionBuf = Buffer.allocUnsafe(2);
    dekVersionBuf.writeUInt16BE(dekVersion, 0);

    // Concatenate in order
    return Buffer.concat([
      iv,
      authTag,
      dekLen,
      encryptedDek,
      dekVersionBuf,
      ciphertext,
    ]);
  }
}
