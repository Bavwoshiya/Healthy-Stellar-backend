import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  ManyToOne,
  JoinColumn,
  Index,
  ForeignKeyConstraint,
} from 'typeorm';
import { Record } from './record.entity';

export enum AttachmentMimeType {
  PDF = 'application/pdf',
  JPEG = 'image/jpeg',
  PNG = 'image/png',
  DICOM = 'application/dicom',
}

@Entity('record_attachments')
@Index(['recordId'])
@Index(['recordId', 'isDeleted'])
@Index(['uploadedAt'])
export class RecordAttachment {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  recordId: string;

  @ManyToOne(() => Record, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'recordId' })
  record: Record;

  @Column()
  originalFilename: string;

  @Column({ type: 'enum', enum: AttachmentMimeType })
  mimeType: AttachmentMimeType;

  @Column()
  cid: string;

  @Column({ type: 'bigint' })
  fileSize: number;

  @Column()
  uploadedBy: string;

  @Column({ default: false })
  @Index()
  isDeleted: boolean;

  @CreateDateColumn()
  uploadedAt: Date;
}
