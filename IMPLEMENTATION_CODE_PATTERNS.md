# Code Examples - Implementation Patterns

## 1. EXISTING IMPLEMENTATION PATTERNS TO FOLLOW

### Pattern 1: Multer File Upload with Validation

```typescript
// ✅ Existing: Records Controller
@Post()
@UseInterceptors(
  FileInterceptor('file', {
    limits: {
      fileSize: 10 * 1024 * 1024, // 10MB
    },
  }),
)
async uploadRecord(
  @Body() dto: CreateRecordDto,
  @UploadedFile() file: Express.Multer.File
) {
  if (!file) {
    throw new BadRequestException('Encrypted record file is required');
  }
  return this.recordsService.uploadRecord(dto, file.buffer);
}

// ✅ Existing: File Upload Service
private validateFile(file: Express.Multer.File): void {
  const maxSize = 10 * 1024 * 1024; // 10MB
  const allowedMimeTypes = [
    'image/jpeg',
    'image/png',
    'image/gif',
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'text/plain',
  ];

  if (file.size > maxSize) {
    throw new BadRequestException('File size exceeds maximum allowed size (10MB)');
  }

  if (!allowedMimeTypes.includes(file.mimetype)) {
    throw new BadRequestException(`File type ${file.mimetype} is not allowed`);
  }
}
```

---

### Pattern 2: Role-Based Access Control

```typescript
// ✅ Existing: Authorization Gates
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(UserRole.PHYSICIAN, UserRole.ADMIN)
@Post('/records')
async uploadRecord(@Body() dto: CreateRecordDto) {
  // Only PHYSICIAN and ADMIN roles reach here
}

@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(UserRole.PATIENT)
@Get('/my-records')
async getMyRecords(@Req() req) {
  // Only PATIENT role reaches here
  // req.user contains: { sub, email, role, sessionId, iat, exp }
}

// ✅ Existing: RolesGuard Implementation
@Injectable()
export class RolesGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest();
    const user: JwtPayload = request.user;
    const requiredRoles = Reflect.getMetadata('roles', context.getHandler()) || [];

    if (requiredRoles.length === 0) return true;

    const hasRole = requiredRoles.includes(user.role);
    if (!hasRole) {
      throw new ForbiddenException(
        `Access denied. Required roles: ${requiredRoles.join(', ')}`
      );
    }
    return true;
  }
}

// Extract user from request
const uploadedBy = req.user?.id || 'system';
```

---

### Pattern 3: Encryption Service Usage

```typescript
// ✅ Existing: Encryption Service Call
import { EncryptionService } from '../../encryption/services/encryption.service';

@Injectable()
export class RecordsService {
  constructor(private encryptionService: EncryptionService) {}

  async uploadRecord(
    dto: CreateRecordDto,
    plainBuffer: Buffer
  ): Promise<{ recordId: string; cid: string }> {
    // Encrypt the record
    const encryptedRecord = await this.encryptionService.encryptRecord(
      plainBuffer,
      dto.patientId
    );

    // Upload ciphertext to IPFS
    const cid = await this.ipfsService.upload(encryptedRecord.ciphertext);

    // Store metadata in PostgreSQL
    const record = this.recordRepository.create({
      patientId: dto.patientId,
      cid,
      // Store encrypted DEK components (NOT in IPFS)
      encryptedDek: encryptedRecord.encryptedDek.toString('hex'),
      iv: encryptedRecord.iv.toString('hex'),
      authTag: encryptedRecord.authTag.toString('hex'),
      dekVersion: encryptedRecord.dekVersion,
    });

    const saved = await this.recordRepository.save(record);
    return {
      recordId: saved.id,
      cid: saved.cid,
    };
  }
}

// ✅ Encryption Service API
interface EncryptedRecord {
  ciphertext: Buffer;        // The encrypted payload
  encryptedDek: Buffer;      // DEK encrypted with patient's KEK
  iv: Buffer;                // 12-byte initialization vector
  authTag: Buffer;           // 16-byte authentication tag
  dekVersion: string;        // Key version identifier
}

// Usage
const encryptedRecord = await encryptionService.encryptRecord(plainBuffer, patientId);
const plainBuffer = await encryptionService.decryptRecord(encryptedRecord, patientId);
```

---

### Pattern 4: IPFS Upload Flow

```typescript
// ✅ Existing: IPFS Service
@Injectable()
export class IpfsService {
  private ipfs: any;

  constructor(private tracingService: TracingService) {
    this.ipfs = create({
      host: process.env.IPFS_HOST || 'localhost',
      port: parseInt(process.env.IPFS_PORT || '5001'),
      protocol: process.env.IPFS_PROTOCOL || 'http',
    });
  }

  async upload(buffer: Buffer): Promise<string> {
    return this.tracingService.withSpan('ipfs.upload', async (span) => {
      span.setAttribute('ipfs.buffer_size', buffer.length);
      span.setAttribute('ipfs.host', process.env.IPFS_HOST || 'localhost');

      try {
        this.tracingService.addEvent('ipfs.add.start');
        const result = await this.ipfs.add(buffer);
        const cid = result.path;

        span.setAttribute('ipfs.cid', cid);
        this.tracingService.addEvent('ipfs.add.complete', { 'ipfs.cid': cid });
        this.logger.log(`File uploaded to IPFS with CID: ${cid}`);

        return cid;
      } catch (error) {
        this.tracingService.recordException(error as Error);
        this.logger.error(`IPFS upload failed: ${error.message}`);
        throw new Error(`IPFS upload failed: ${error.message}`);
      }
    });
  }
}

// ✅ Circuit Breaker Wrapper
@Injectable()
export class IpfsWithBreakerService {
  async upload(buffer: Buffer): Promise<string> {
    return this.circuitBreaker.execute(
      'ipfs',
      () => this.ipfsService.upload(buffer)
    );
  }
}

// ✅ Usage in Service
const cid = await this.ipfsService.upload(encryptedBuffer);
```

---

### Pattern 5: File Entity Creation & Storage

```typescript
// ✅ Existing: Medical Attachment Entity Creation
@Injectable()
export class FileUploadService {
  async uploadFile(
    file: Express.Multer.File,
    recordId: string,
    attachmentType: AttachmentType,
    description?: string,
    uploadedBy: string = 'system',
  ): Promise<MedicalAttachment> {
    // Verify record exists
    await this.medicalRecordsService.findOne(recordId);

    // Validate file
    this.validateFile(file);

    // Generate unique filename
    const fileExtension = extname(file.originalname);
    const uniqueFileName = `${uuidv4()}${fileExtension}`;
    const filePath = join(this.uploadPath, uniqueFileName);

    // Save file to disk
    writeFileSync(filePath, file.buffer);

    // Create attachment record in DB
    const attachment = this.attachmentRepository.create({
      medicalRecordId: recordId,
      fileName: uniqueFileName,
      originalFileName: file.originalname,
      mimeType: file.mimetype,
      fileSize: file.size,
      filePath,
      fileUrl: `/uploads/${uniqueFileName}`,
      attachmentType,
      description,
      uploadedBy,
    });

    const saved = await this.attachmentRepository.save(attachment);
    this.logger.log(`File uploaded: ${saved.id} for record ${recordId}`);

    return saved;
  }
}
```

---

## 2. PATTERN FOR NEW RECORD ATTACHMENT ENDPOINT

### Recommended Implementation

```typescript
// 1. CREATE DTO
export class CreateRecordAttachmentDto {
  @IsString()
  recordId: string;

  @IsEnum(AttachmentType)
  attachmentType: AttachmentType;

  @IsOptional()
  @IsString()
  description?: string;
}

// 2. CREATE ENTITY
@Entity('record_attachments')
@Index(['recordId', 'createdAt'])
export class RecordAttachment {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  @Index()
  recordId: string;

  @ManyToOne(() => Record, (record) => record.attachments, {
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'recordId' })
  record: Record;

  // IPFS storage
  @Column({ type: 'varchar', length: 500 })
  ipfsCid: string;

  // Encryption metadata (stored in DB, not on IPFS)
  @Column({ type: 'varchar', length: 500 })
  encryptedDek: string;  // Hex-encoded

  @Column({ type: 'varchar', length: 50 })
  iv: string;  // Hex-encoded

  @Column({ type: 'varchar', length: 50 })
  authTag: string;  // Hex-encoded

  @Column({ type: 'varchar', length: 20 })
  dekVersion: string;

  // File metadata
  @Column({ type: 'varchar', length: 255 })
  originalFileName: string;

  @Column({ type: 'varchar', length: 100 })
  mimeType: string;

  @Column({ type: 'bigint' })
  fileSize: number;

  @Column({
    type: 'enum',
    enum: AttachmentType,
    default: AttachmentType.OTHER,
  })
  attachmentType: AttachmentType;

  @Column({ type: 'text', nullable: true })
  description: string;

  @Column({ type: 'uuid' })
  uploadedBy: string;

  @Column({ type: 'boolean', default: true })
  isActive: boolean;

  @Column({ type: 'jsonb', nullable: true })
  metadata: Record<string, any>;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}

// 3. CREATE SERVICE
@Injectable()
export class RecordAttachmentService {
  constructor(
    @InjectRepository(RecordAttachment)
    private attachmentRepository: Repository<RecordAttachment>,
    @InjectRepository(Record)
    private recordRepository: Repository<Record>,
    private encryptionService: EncryptionService,
    private ipfsService: IpfsService,
    private accessControlService: AccessControlService,
    private auditLogService: AuditLogService,
  ) {}

  async uploadAttachment(
    file: Express.Multer.File,
    dto: CreateRecordAttachmentDto,
    uploadedByUserId: string,
  ): Promise<RecordAttachment> {
    // 1. Verify record exists
    const record = await this.recordRepository.findOne({
      where: { id: dto.recordId },
    });
    if (!record) {
      throw new NotFoundException(`Record ${dto.recordId} not found`);
    }

    // 2. Verify access (can user write to this record?)
    const canWrite = await this.accessControlService.canWrite(
      uploadedByUserId,
      dto.recordId
    );
    if (!canWrite) {
      throw new ForbiddenException('You do not have write access to this record');
    }

    // 3. Validate file
    this.validateFile(file);

    // 4. Encrypt file
    const encryptedRecord = await this.encryptionService.encryptRecord(
      file.buffer,
      record.patientId
    );

    // 5. Upload encrypted content to IPFS
    const ipfsCid = await this.ipfsService.upload(
      encryptedRecord.ciphertext
    );

    // 6. Create attachment record (with encryption metadata, NOT ciphertext)
    const attachment = this.attachmentRepository.create({
      recordId: dto.recordId,
      ipfsCid,
      encryptedDek: encryptedRecord.encryptedDek.toString('hex'),
      iv: encryptedRecord.iv.toString('hex'),
      authTag: encryptedRecord.authTag.toString('hex'),
      dekVersion: encryptedRecord.dekVersion,
      originalFileName: file.originalname,
      mimeType: file.mimetype,
      fileSize: file.size,
      attachmentType: dto.attachmentType,
      description: dto.description,
      uploadedBy: uploadedByUserId,
    });

    const saved = await this.attachmentRepository.save(attachment);

    // 7. Audio log
    await this.auditLogService.log({
      action: 'ATTACHMENT_UPLOADED',
      resourceType: 'RecordAttachment',
      resourceId: saved.id,
      userId: uploadedByUserId,
      recordId: dto.recordId,
      details: {
        fileName: file.originalname,
        ipfsCid,
      },
    });

    this.logger.log(
      `Attachment ${saved.id} uploaded to record ${dto.recordId} by ${uploadedByUserId}`
    );

    return saved;
  }

  async getAttachmentStream(
    attachmentId: string,
    requestingUserId: string,
  ): Promise<{ stream: Readable; fileName: string }> {
    // 1. Fetch attachment
    const attachment = await this.attachmentRepository.findOne({
      where: { id: attachmentId, isActive: true },
      relations: ['record'],
    });
    if (!attachment) {
      throw new NotFoundException(`Attachment ${attachmentId} not found`);
    }

    // 2. Verify access
    const canRead = await this.accessControlService.canRead(
      requestingUserId,
      attachment.recordId
    );
    if (!canRead) {
      throw new ForbiddenException('You do not have read access to this attachment');
    }

    // 3. Fetch from IPFS
    const ciphertext = await this.ipfsService.fetch(attachment.ipfsCid);

    // 4. Construct EncryptedRecord from DB metadata
    const encryptedRecord: EncryptedRecord = {
      ciphertext,
      encryptedDek: Buffer.from(attachment.encryptedDek, 'hex'),
      iv: Buffer.from(attachment.iv, 'hex'),
      authTag: Buffer.from(attachment.authTag, 'hex'),
      dekVersion: attachment.dekVersion,
    };

    // 5. Decrypt
    const plaintext = await this.encryptionService.decryptRecord(
      encryptedRecord,
      attachment.record.patientId
    );

    // 6. Create readable stream
    const stream = Readable.from(plaintext);

    // 7. Audit log
    await this.auditLogService.log({
      action: 'ATTACHMENT_DOWNLOADED',
      resourceType: 'RecordAttachment',
      resourceId: attachmentId,
      userId: requestingUserId,
    });

    return { stream, fileName: attachment.originalFileName };
  }

  private validateFile(file: Express.Multer.File): void {
    const maxSize = 10 * 1024 * 1024;
    const allowedMimeTypes = [
      'image/jpeg',
      'image/png',
      'image/gif',
      'application/pdf',
      'application/msword',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'text/plain',
    ];

    if (file.size > maxSize) {
      throw new BadRequestException('File size exceeds 10MB limit');
    }

    if (!allowedMimeTypes.includes(file.mimetype)) {
      throw new BadRequestException(
        `File type ${file.mimetype} is not allowed`
      );
    }
  }
}

// 4. CREATE CONTROLLER
@ApiTags('Record Attachments')
@Controller('records/:recordId/attachments')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(UserRole.PHYSICIAN, UserRole.ADMIN)
@ApiBearerAuth()
export class RecordAttachmentController {
  constructor(
    private recordAttachmentService: RecordAttachmentService,
  ) {}

  @Post()
  @UseInterceptors(
    FileInterceptor('file', {
      limits: { fileSize: 10 * 1024 * 1024 },
    }),
  )
  @ApiOperation({ summary: 'Upload encrypted attachment to record' })
  @ApiConsumes('multipart/form-data')
  @ApiBody({
    schema: {
      type: 'object',
      required: ['file', 'attachmentType'],
      properties: {
        file: { type: 'string', format: 'binary' },
        attachmentType: {
          type: 'string',
          enum: Object.values(AttachmentType),
        },
        description: { type: 'string' },
      },
    },
  })
  @ApiResponse({ status: 201, description: 'Attachment uploaded' })
  async uploadAttachment(
    @Param('recordId') recordId: string,
    @Body() dto: CreateRecordAttachmentDto,
    @UploadedFile() file: Express.Multer.File,
    @Req() req,
  ) {
    if (!file) {
      throw new BadRequestException('File is required');
    }

    dto.recordId = recordId;
    const uploadedByUserId = req.user.sub;

    return this.recordAttachmentService.uploadAttachment(
      file,
      dto,
      uploadedByUserId
    );
  }

  @Get(':attachmentId')
  @ApiOperation({ summary: 'Download encrypted attachment' })
  @ApiResponse({ status: 200, description: 'File stream' })
  async downloadAttachment(
    @Param('attachmentId') attachmentId: string,
    @Res() res: Response,
    @Req() req,
  ) {
    const { stream, fileName } = await this.recordAttachmentService.getAttachmentStream(
      attachmentId,
      req.user.sub
    );

    res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');

    stream.pipe(res);
  }

  @Get()
  @ApiOperation({ summary: 'List attachments for record' })
  async listAttachments(
    @Param('recordId') recordId: string,
    @Req() req,
  ) {
    // Verify access and list
    return this.recordAttachmentService.listAttachments(
      recordId,
      req.user.sub
    );
  }
}

// 5. ADD TO MODULE
@Module({
  imports: [
    TypeOrmModule.forFeature([RecordAttachment, Record]),
    EncryptionModule,
    AccessControlModule,
    AuditModule,
  ],
  controllers: [RecordAttachmentController],
  providers: [RecordAttachmentService],
  exports: [RecordAttachmentService],
})
export class RecordAttachmentModule {}
```

---

## 3. DATA FLOW DIAGRAMS

### Upload Flow with Encryption + IPFS

```
Client
  ↓
POST /records/:id/attachments (multipart/form-data)
  ├─ file (binary)
  ├─ attachmentType
  └─ description
  ↓
JwtAuthGuard → extracts token → request.user
  ↓
RolesGuard → checks @Roles(PHYSICIAN, ADMIN) → ✅ or 403
  ↓
FileInterceptor → validates size (10MB) → ✅ or 413
  ↓
RecordAttachmentService.uploadAttachment()
  ├─ Verify record exists ✅
  ├─ Verify write access (AccessControlService) ✅
  ├─ Validate MIME type ✅
  ├─ EncryptionService.encryptRecord(file.buffer, patientId)
  │   ├─ Generate DEK (32 bytes)
  │   ├─ Generate IV (12 bytes)
  │   ├─ AES-256-GCM encrypt
  │   ├─ Extract authTag (16 bytes)
  │   ├─ Wrap DEK with patient KEK
  │   └─ Clear plaintext DEK from memory
  │
  ├─ IpfsService.upload(ciphertext)
  │   └─ Returns CID (distributed, immutable)
  │
  ├─ RecordAttachmentRepository.save()
  │   └─ Store: recordId, ipfsCid, encrypted_dek, iv, auth_tag, dekVersion, fileMetadata
  │
  └─ AuditLogService.log('ATTACHMENT_UPLOADED')

  ↓
Response 201 Created
  {
    "id": "...",
    "recordId": "...",
    "ipfsCid": "Qm...",
    "originalFileName": "...",
    "attachmentType": "IMAGE",
    "createdAt": "...",
    ...
  }
```

### Download Flow with Decryption

```
Client
  ↓
GET /records/:id/attachments/:attachmentId
  ↓
JwtAuthGuard → validates token
  ↓
RolesGuard → checks PHYSICIAN/ADMIN ✅
  ↓
RecordAttachmentService.getAttachmentStream()
  ├─ Fetch RecordAttachment from DB
  │   └─ Contains: ipfsCid, encrypted_dek, iv, auth_tag, dekVersion, patientId
  │
  ├─ AccessControlService.canRead(userId, recordId) ✅
  │
  ├─ IpfsService.fetch(ipfsCid)
  │   └─ Retrieve ciphertext from IPFS (decentralized)
  │
  ├─ EncryptionService.decryptRecord()
  │   ├─ Use encrypted_dek + iv + auth_tag from DB
  │   ├─ KEK.unwrap(encrypted_dek) → plaintext DEK
  │   ├─ AES-256-GCM decrypt(ciphertext)
  │   ├─ Verify authTag
  │   ├─ Clear plaintext DEK from memory
  │   └─ Return plaintext buffer
  │
  ├─ Readable.from(plaintext) → stream
  │
  └─ AuditLogService.log('ATTACHMENT_DOWNLOADED')

  ↓
Response 200 OK
  Accept-Ranges: bytes
  Content-Type: image/jpeg
  Content-Disposition: attachment; filename="patient-photo.jpg"
  Cache-Control: no-store, no-cache, must-revalidate
  [stream of plaintext]
```

---

## 4. ERROR HANDLING PATTERNS

```typescript
// ✅ Pattern: Validation Errors
throw new BadRequestException('File size exceeds 10MB');
// Response: { "statusCode": 400, "message": "..." }

// ✅ Pattern: Not Found
throw new NotFoundException(`Record ${recordId} not found`);
// Response: { "statusCode": 404, "message": "..." }

// ✅ Pattern: Authorization
throw new ForbiddenException('You do not have write access');
// Response: { "statusCode": 403, "message": "..." }

// ✅ Pattern: Service Errors
throw new IpfsUploadException('Failed to upload to IPFS', {
  ipfsError: error.message,
  fileSize: buffer.length,
});
// Response: { "statusCode": 502, "message": "Bad Gateway", "details": {...} }

// ✅ Pattern: Encryption Errors
throw new EncryptionError('DEK generation failed');
// Response: Handled by global exception filter
```

---

## 5. TESTING TEMPLATES

### Unit Test Example

```typescript
describe('RecordAttachmentService', () => {
  let service: RecordAttachmentService;
  let encryptionService: EncryptionService;
  let ipfsService: IpfsService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        RecordAttachmentService,
        { provide: EncryptionService, useValue: mockEncryptionService },
        { provide: IpfsService, useValue: mockIpfsService },
        // ... other mocks
      ],
    }).compile();

    service = module.get(RecordAttachmentService);
  });

  it('should encrypt file before uploading to IPFS', async () => {
    const file = { buffer: Buffer.from('test'), originalname: 'test.jpg' };
    const encryptedRecord = { ciphertext: Buffer.from('encrypted') };

    jest.spyOn(encryptionService, 'encryptRecord')
      .mockResolvedValue(encryptedRecord);
    jest.spyOn(ipfsService, 'upload')
      .mockResolvedValue('QmXxx...');

    await service.uploadAttachment(file, dto, userId);

    expect(encryptionService.encryptRecord).toHaveBeenCalledWith(
      file.buffer,
      patientId
    );
    expect(ipfsService.upload).toHaveBeenCalledWith(encryptedRecord.ciphertext);
  });

  it('should verify access before allowing upload', async () => {
    jest.spyOn(accessControlService, 'canWrite').mockResolvedValue(false);

    await expect(
      service.uploadAttachment(file, dto, userId)
    ).rejects.toThrow(ForbiddenException);
  });
});
```

### E2E Test Example

```typescript
describe('POST /records/:id/attachments', () => {
  it('should upload and encrypt file with provider role', async () => {
    const response = await request(app.getHttpServer())
      .post(`/records/${recordId}/attachments`)
      .set('Authorization', `Bearer ${physicianToken}`)
      .field('attachmentType', 'IMAGE')
      .field('description', 'Patient photo')
      .attach('file', fileBuffer, 'photo.jpg')
      .expect(201);

    expect(response.body).toHaveProperty('id');
    expect(response.body).toHaveProperty('ipfsCid');
    expect(response.body.attachmentType).toBe('IMAGE');
    expect(response.body.originalFileName).toBe('photo.jpg');
  });

  it('should reject upload without provider role', async () => {
    await request(app.getHttpServer())
      .post(`/records/${recordId}/attachments`)
      .set('Authorization', `Bearer ${patientToken}`)
      .attach('file', fileBuffer, 'photo.jpg')
      .expect(403);
  });

  it('should reject file >10MB', async () => {
    const largeBuffer = Buffer.alloc(11 * 1024 * 1024);

    await request(app.getHttpServer())
      .post(`/records/${recordId}/attachments`)
      .set('Authorization', `Bearer ${physicianToken}`)
      .attach('file', largeBuffer, 'large.bin')
      .expect(413);
  });
});
```

