# Healthy-Stellar Backend Codebase Exploration

## 1. RECORDS MODULE STRUCTURE

### Module Import/Export
**File:** [src/records/records.module.ts](src/records/records.module.ts)

```typescript
@Module({
  imports: [
    TypeOrmModule.forFeature([Record, RecordEvent, RecordSnapshot, RecordTemplate]),
    MulterModule.register({ limits: { fileSize: 10 * 1024 * 1024 } }),
    EventEmitterModule.forRoot(),
    CircuitBreakerModule,
    forwardRef(() => AccessControlModule),
    MedicalRbacModule,
    EncryptionModule,
    AuditModule,
  ],
  controllers: [RecordsController, RecordTemplateController],
  providers: [
    RecordsService,
    RelatedRecordsService,
    RecordTemplateService,
    IpfsService,
    StellarService,
    IpfsWithBreakerService,
    RecordEventStoreService,
    RecordDownloadService,
    RecordSyncService,
  ],
  exports: [
    RecordsService,
    RelatedRecordsService,
    RecordTemplateService,
    IpfsWithBreakerService,
    RecordEventStoreService,
    RecordDownloadService,
    RecordSyncService,
  ],
})
export class RecordsModule {}
```

### Records Controller Endpoints
**File:** [src/records/controllers/records.controller.ts](src/records/controllers/records.controller.ts)

#### POST - Upload Record
```typescript
@Post()
@UseInterceptors(FileInterceptor('file', { limits: { fileSize: 10 * 1024 * 1024 } }))
async uploadRecord(@Body() dto: CreateRecordDto, @UploadedFile() file: Express.Multer.File)
// Parameters: CreateRecordDto { patientId, recordType, description? }, Buffer (file.buffer)
// Returns: { recordId, cid, stellarTxHash }
```

#### GET - List Records (Deprecated)
```typescript
@Get()
@DeprecatedRoute(/* deprecation info */)
async findAll(@Query() query: PaginationQueryDto): Promise<PaginatedRecordsResponseDto>
// Query params: page, pageSize, recordType, fromDate, toDate, patientId, sortBy, order
```

#### GET - Search Records
```typescript
@Get('search')
@UseGuards(JwtAuthGuard)
async searchRecords(@Query() dto: SearchRecordsDto, @Req() req): Promise<SearchRecordsResponseDto>
// Search params: patientAddress, providerAddress, type, from, to, q, page, pageSize
// Admin/Physician: search all records
// Patient: auto-scoped to own records only
```

#### GET - Records by ID
```typescript
@Get(':id')
async findOne(@Param('id') id: string, @Req() req, @Query('includeDeleted') includeDeleted?: string)
// Admin only can pass includeDeleted=true
// Returns: Record entity
```

#### GET - Download/Stream Record
```typescript
@Get(':id/download')
@UseGuards(JwtAuthGuard)
async downloadRecord(@Param('id') id: string, @Req() req, @Res() res: Response): Promise<void>
// Sets headers: Content-Type, Content-Disposition (attachment), Cache-Control
// Streams decrypted content to client
```

#### GET - QR Code
```typescript
@Get(':id/qr-code')
async getQrCode(@Param('id') id: string, @Req() req): Promise<{ qrCode: string }>
// Returns Base64 PNG QR code for one-time share link
```

#### GET - Recent Records (Admin)
```typescript
@Get('recent')
@UseGuards(MedicalRbacGuard)
@MedicalRoles(MedicalRole.ADMIN)
async getRecent(): Promise<RecentRecordDto[]>
```

#### GET - Related Records
```typescript
@Get(':id/related')
@UseGuards(JwtAuthGuard)
async getRelated(@Param('id') id: string, @Req() req): Promise<RelatedRecordDto[]>
// Scoring: same type (3pts), same provider (2pts), within ±30 days (1pt)
// Returns up to 10 related records with access control enforced
```

#### GET - Event Stream (Admin)
```typescript
@Get(':id/events')
@UseGuards(JwtAuthGuard, AdminGuard)
async getEventStream(@Param('id') id: string): Promise<RecordEvent[]>
// Full immutable event log for a record
```

#### GET - Record State (from Event Replay)
```typescript
@Get(':id/state')
async getStateFromEvents(@Param('id') id: string): Promise<RecordState>
// Current state derived by replaying event stream
```

### Record Entity
**File:** [src/records/entities/record.entity.ts](src/records/entities/record.entity.ts)

```typescript
@Entity('records')
export class Record {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  patientId: string;

  @Column({ nullable: true })
  providerId: string;

  @Column()
  cid: string;  // IPFS Content Identifier

  @Column({ nullable: true })
  stellarTxHash: string;

  @Column({ type: 'enum', enum: RecordType })
  recordType: RecordType;  // MEDICAL_REPORT, LAB_RESULT, PRESCRIPTION, IMAGING, CONSULTATION

  @Column({ nullable: true })
  description: string;

  @Column({ default: false })
  @Index()
  isDeleted: boolean;

  @Column({ type: 'timestamp with time zone', nullable: true })
  deletedOnChainAt: Date | null;

  @CreateDateColumn()
  createdAt: Date;
}
```

### RecordsService Methods
**File:** [src/records/services/records.service.ts](src/records/services/records.service.ts)

#### uploadRecord
```typescript
async uploadRecord(
  dto: CreateRecordDto,
  encryptedBuffer: Buffer,
  causedBy?: string
): Promise<{ recordId: string; cid: string; stellarTxHash: string }>
```

#### findAll
```typescript
async findAll(query: PaginationQueryDto): Promise<PaginatedRecordsResponseDto>
```

#### findOne
```typescript
async findOne(id: string, requesterId?: string, includeDeleted = false): Promise<Record>
```

#### search
```typescript
async search(
  dto: SearchRecordsDto,
  callerId: string,
  callerRole: string
): Promise<SearchRecordsResponseDto>
```

#### generateQrCode
```typescript
async generateQrCode(id: string, patientId: string): Promise<string>
```

#### getStateFromEvents
```typescript
async getStateFromEvents(id: string): Promise<RecordState>
```

#### getEventStream
```typescript
async getEventStream(id: string): Promise<RecordEvent[]>
```

---

## 2. ENCRYPTION & CRYPTOGRAPHY

### Module Location
**File:** [src/encryption/encryption.module.ts](src/encryption/encryption.module.ts)

```typescript
@Module({
  providers: [EncryptionService, KeyManagementService],
  exports: [EncryptionService],  // KeyManagementService is private
})
export class EncryptionModule {}
```

**Note:** KeyManagementService is intentionally NOT exported to enforce security boundaries.

### Encryption Service
**File:** [src/encryption/services/encryption.service.ts](src/encryption/services/encryption.service.ts)

#### encryptRecord Method
```typescript
async encryptRecord(
  payload: Buffer,
  patientId: string
): Promise<EncryptedRecord>

// Process:
// 1. Generate unique 32-byte (256-bit) DEK using crypto.randomBytes
// 2. Generate unique 12-byte IV using crypto.randomBytes
// 3. Encrypt payload using AES-256-GCM with DEK and IV
// 4. Extract authentication tag (16 bytes)
// 5. Call kms.wrapDek to encrypt DEK with patient's KEK
// 6. Get DEK version identifier
// 7. Clear plaintext DEK from memory
// 8. Return EncryptedRecord structure
```

#### decryptRecord Method
```typescript
async decryptRecord(
  encryptedRecord: EncryptedRecord,
  patientId: string
): Promise<Buffer>

// Process:
// 1. Validate EncryptedRecord structure
// 2. Call kms.unwrapDek to decrypt encrypted DEK
// 3. Create AES-256-GCM decipher
// 4. Set authentication tag for verification
// 5. Decrypt ciphertext
// 6. Verify authentication tag (throws AuthenticationError if invalid)
// 7. Clear plaintext DEK from memory
// 8. Return plaintext payload
```

### Key Management Service (Private)
**File:** [src/encryption/services/key-management.service.ts](src/encryption/services/key-management.service.ts)

#### wrapDek Method
```typescript
async wrapDek(dek: Buffer, patientId: string): Promise<Buffer>

// Returns: Buffer containing [iv:12 bytes][encryptedDek][authTag:16 bytes]
// Encrypts DEK with patient's KEK using AES-256-GCM
// Throws KeyManagementError if KEK not found
```

#### unwrapDek Method
```typescript
async unwrapDek(encryptedDek: Buffer, patientId: string): Promise<Buffer>

// Input: Buffer containing [iv:12 bytes][encryptedDek][authTag:16 bytes]
// Extracts IV, encrypted DEK, and auth tag
// Decrypts using patient's KEK
// Verifies authentication tag
// Returns plaintext DEK
// Throws KeyManagementError if verification fails
```

#### initializeTestKeks Method
```typescript
initializeTestKeks(patientIds: string[]): void
// Generates and stores 256-bit KEK for each patient ID
// Used for development/testing
```

### Key Management Module
**File:** [src/key-management/key-management.module.ts](src/key-management/key-management.module.ts)

```typescript
@Module({
  imports: [ConfigModule, CircuitBreakerModule, CommonModule, TenantModule],
  providers: [
    {
      provide: 'KeyManagementService',
      useClass: AwsKmsService,  // Production: integrates with AWS KMS
    },
  ],
  exports: ['KeyManagementService'],
})
export class KeyManagementModule {}
```

### EncryptedRecord Interface
**File:** [src/encryption/interfaces/encrypted-record.interface.ts](src/encryption/interfaces/encrypted-record.interface.ts)

```typescript
export interface EncryptedRecord {
  iv: Buffer;                    // 12 bytes, initialization vector
  ciphertext: Buffer;            // Encrypted payload
  authTag: Buffer;               // 16 bytes, authentication tag (AES-256-GCM)
  encryptedDek: Buffer;          // DEK encrypted with patient's KEK
  dekVersion: string;            // Version identifier for key rotation
}
```

### Patient DEK Retrieval
Located in [src/encryption/services/key-management.service.ts](src/encryption/services/key-management.service.ts):
- Patient KEKs stored in in-memory Map: `private readonly keks: Map<string, Buffer>`
- In production: would use AWS KMS, Azure Key Vault, or HSM
- DEK unwrapping: `unwrapDek(encryptedDek, patientId)` retrieves from stored KEK

---

## 3. IPFS INTEGRATION

### IPFS Service
**File:** [src/records/services/ipfs.service.ts](src/records/services/ipfs.service.ts)

```typescript
@Injectable()
export class IpfsService {
  constructor(private readonly tracingService: TracingService) {
    this.ipfs = create({
      host: process.env.IPFS_HOST || 'localhost',
      port: parseInt(process.env.IPFS_PORT || '5001'),
      protocol: process.env.IPFS_PROTOCOL || 'http',
    });
  }

  async upload(buffer: Buffer): Promise<string>
  // Uploads encrypted buffer to IPFS
  // Returns: CID (Content Identifier)
  // Includes distributed tracing events
}
```

### IPFS with Circuit Breaker
**File:** [src/records/services/ipfs-with-breaker.service.ts](src/records/services/ipfs-with-breaker.service.ts)

```typescript
async upload(buffer: Buffer): Promise<string>
// Wraps IpfsService.upload with circuit breaker pattern
// Prevents cascading failures in IPFS network
// Throws CircuitOpenException if circuit is open
```

### IPFS Fetch Operations
**File:** [src/records/services/record-download.service.ts](src/records/services/record-download.service.ts#L75-L80)

```typescript
async fetchFromIpfs(cid: string): Promise<Buffer>
// Streams chunks from IPFS using ipfs.cat(cid)
// Concatenates all chunks into single Buffer
// In-memory operation (no disk write)
```

### Other IPFS Implementations
- [src/medical-records/services/ipfs.service.ts](src/medical-records/services/ipfs.service.ts)
- [src/stellar/services/ipfs.service.ts](src/stellar/services/ipfs.service.ts)
- [src/data-residency/services/regional-ipfs.service.ts](src/data-residency/services/regional-ipfs.service.ts)

---

## 4. ACCESS CONTROL

### Access Control Module
**File:** [src/access-control/access-control.module.ts](src/access-control/access-control.module.ts)

```typescript
@Module({
  imports: [
    TypeOrmModule.forFeature([AccessGrant, AccessRequest, User]),
    NotificationsModule,
  ],
  controllers: [
    AccessControlController,
    UsersEmergencyAccessController,
    AccessRequestController,
  ],
  providers: [
    AccessControlService,
    SorobanQueueService,
    EmergencyAccessCleanupService,
    AccessRequestService,
  ],
  exports: [AccessControlService, AccessRequestService],
})
export class AccessControlModule {}
```

### Access Control Service
**File:** [src/access-control/services/access-control.service.ts](src/access-control/services/access-control.service.ts)

#### verifyAccess Method
```typescript
async verifyAccess(requesterId: string, recordId: string): Promise<boolean>

// Process:
// 1. Find all active grants for requester
// 2. Check if any grant contains the recordId
// 3. Verify grant has not expired (expiresAt > now)
// 4. Return true if valid grant exists, false otherwise
```

#### grantAccess Method
```typescript
async grantAccess(
  patientId: string,
  dto: CreateAccessGrantDto
): Promise<AccessGrant>

// Parameters:
// - patientId: Patient granting access
// - dto: { granteeId, recordIds, accessLevel, expiresAt? }
//
// Process:
// 1. Check for conflicting active grants
// 2. Create new AccessGrant in DB
// 3. Dispatch to Soroban blockchain
// 4. Emit notifications
// 5. Log to audit service (tamper-evident)
```

#### revokeAccess Method
```typescript
async revokeAccess(
  grantId: string,
  patientId: string,
  reason?: string
): Promise<AccessGrant>

// Revokes grant, updates status to REVOKED
// Records revocation timestamp and reason
// Dispatches revocation to Soroban
```

#### createEmergencyAccess Method
```typescript
async createEmergencyAccess(
  requestedBy: string,
  dto: CreateEmergencyAccessDto
): Promise<AccessGrant>

// Validates:
// - emergencyReason >= 50 characters
// - Patient has not disabled emergency access
// - No duplicate emergency access
// Creates temporary access grant
// Must be logged to audit system
```

#### findActiveEmergencyGrant Method
```typescript
async findActiveEmergencyGrant(
  patientId: string,
  requesterId: string,
  recordId: string
): Promise<AccessGrant | null>
```

### Access Grant Entity
**File:** [src/access-control/entities/access-grant.entity.ts](src/access-control/entities/access-grant.entity.ts)

```typescript
@Entity('access_grants')
export class AccessGrant {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  @Index()
  patientId: string;

  @Column({ type: 'uuid' })
  @Index()
  granteeId: string;

  @Column({ type: 'simple-array' })
  recordIds: string[];  // Array of record IDs this grant covers

  @Column({ type: 'enum', enum: AccessLevel })
  accessLevel: AccessLevel;  // READ or READ_WRITE

  @Column({ type: 'enum', enum: GrantStatus, default: GrantStatus.ACTIVE })
  status: GrantStatus;  // ACTIVE, REVOKED, EXPIRED

  @Column({ default: false })
  isEmergency: boolean;

  @Column({ type: 'text', nullable: true })
  emergencyReason: string;

  @Column({ type: 'timestamp', nullable: true })
  expiresAt: Date;

  @Column({ type: 'timestamp', nullable: true })
  revokedAt: Date;

  @Column({ type: 'uuid', nullable: true })
  revokedBy: string;

  @Column({ type: 'text', nullable: true })
  revocationReason: string;

  @Column({ type: 'varchar', nullable: true })
  sorobanTxHash: string;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}

export enum AccessLevel {
  READ = 'READ',
  READ_WRITE = 'READ_WRITE',
}

export enum GrantStatus {
  ACTIVE = 'ACTIVE',
  REVOKED = 'REVOKED',
  EXPIRED = 'EXPIRED',
}
```

### Medical RBAC Guard
**File:** [src/guards/medical-rbac.guard.ts](src/guards/medical-rbac.guard.ts)

- Used with `@UseGuards(MedicalRbacGuard)` decorator
- Validates user role and permissions
- Decorator: `@MedicalRoles(MedicalRole.ADMIN)` for role-based access

---

## 5. AUDIT LOGGING

### Main Audit Service
**File:** [src/common/audit/audit.service.ts](src/common/audit/audit.service.ts)

```typescript
@Injectable()
export class AuditService {
  async log(event: AuditEventDto): Promise<AuditLogEntity>
  async logAuthenticationEvent(action, success, metadata): Promise<AuditLogEntity>
  async logDataAccess(userId, resourceType, resourceId, ip, ua, metadata?): Promise<AuditLogEntity>
  async logDataExport(userId, resourceType, resourceIds, ip, ua, metadata?): Promise<AuditLogEntity>
  async logUserManagement(userId, action, targetUserId, ip, ua, metadata?): Promise<AuditLogEntity>
}
```

### Audit Log Service (Alternative)
**File:** [src/common/services/audit-log.service.ts](src/common/services/audit-log.service.ts)

```typescript
@Injectable()
export class AuditLogService {
  async create(auditLogData: CreateAuditLogDto): Promise<AuditLog>
  // Parameters:
  // - operation: string (e.g., 'EMERGENCY_ACCESS', 'GRANT_CHANGE', 'GRANT_REVOKE')
  // - entityType: string (e.g., 'records', 'AccessGrant')
  // - entityId: string
  // - userId: string
  // - ipAddress?: string
  // - userAgent?: string
  // - changes?: Record<string, any>
  // - oldValues?: Record<string, any>
  // - newValues?: Record<string, any>
  // - status?: string
  // - errorMessage?: string
  // - executionTimeMs?: number

  async findByEntity(entityType: string, entityId: string): Promise<AuditLog[]>
  async findByUser(userId: string, limit?: number): Promise<AuditLog[]>
  async findByOperation(operation: string, limit?: number): Promise<AuditLog[]>
  async findByDateRange(startDate: Date, endDate: Date): Promise<AuditLog[]>
  async getStatistics(): Promise<any>
  
  // Tamper-evident audit log (INSERT-only at DB level)
  async log(entry: SensitiveAuditEntry): Promise<SensitiveAuditLog>
  // Parameters:
  // - actorAddress: string
  // - action: string
  // - targetAddress?: string
  // - resourceType?: string
  // - resourceId?: string
  // - ipAddress?: string
  // - metadata?: Record<string, any>
}
```

### Audit Log Entity
**File:** [src/common/audit/audit-log.entity.ts](src/common/audit/audit-log.entity.ts)

```typescript
@Entity('audit_logs')
export class AuditLogEntity {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ nullable: true })
  userId: string;

  @Column()
  action: string;

  @Column()
  entity: string;

  @Column({ nullable: true })
  entityId: string;

  @Column({ type: 'text', nullable: true })
  description: string;

  @Column('json', { nullable: true })
  details: Record<string, any>;

  @Column()
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

  @Column({ nullable: true })
  userAgent: string;

  @CreateDateColumn()
  timestamp: Date;

  @Column({ nullable: true })
  ipAddress: string;

  @Column({ default: false })
  reviewed: boolean;

  @Column({ nullable: true })
  reviewedBy: string;

  @Column({ type: 'timestamp', nullable: true })
  reviewedAt: Date;

  @Column({ type: 'jsonb', nullable: true })
  metadata: Record<string, any>;

  @Column({ nullable: true })
  resourceId: string;

  @Column({ nullable: true })
  resourceType: string;

  @Column({ nullable: true })
  stellarTxHash: string;

  @Column({ default: false })
  requiresInvestigation: boolean;

  @CreateDateColumn({ type: 'timestamp with time zone' })
  createdAt: Date;
}

export enum AuditAction {
  LOGIN = 'LOGIN',
  LOGOUT = 'LOGOUT',
  LOGIN_FAILED = 'LOGIN_FAILED',
  USER_CREATED = 'USER_CREATED',
  PASSWORD_CHANGE = 'PASSWORD_CHANGE',
  ACCOUNT_LOCKED = 'ACCOUNT_LOCKED',
  MFA_ENABLED = 'MFA_ENABLED',
  MFA_VERIFIED = 'MFA_VERIFIED',
  MFA_DISABLED = 'MFA_DISABLED',
  DATA_ACCESS = 'DATA_ACCESS',
  DATA_EXPORT = 'DATA_EXPORT',
  UNAUTHORIZED_ACCESS_ATTEMPT = 'UNAUTHORIZED_ACCESS_ATTEMPT',
  API_KEY_CREATED = 'API_KEY_CREATED',
  API_KEY_REVOKED = 'API_KEY_REVOKED',
  API_KEY_USED = 'API_KEY_USED',
}
```

### Existing Audit Log Patterns

**Pattern 1: Record FileDownload**
```typescript
// From record-download.service.ts
await this.auditService.logDataAccess(
  requesterId,
  'Record',
  recordId,
  ip,
  ua,
  { patientId: record.patientId, recordType: record.recordType }
);
```

**Pattern 2: Emergency Access**
```typescript
// From records.service.ts
await this.auditLogService.create({
  operation: 'EMERGENCY_ACCESS',
  entityType: 'records',
  entityId: id,
  userId: requesterId,
  status: 'success',
  newValues: {
    patientId: record.patientId,
    grantId: emergencyGrant.id,
    recordId: id,
  },
});
```

**Pattern 3: Access Control Changes (Tamper-Evident)**
```typescript
// From access-control.service.ts
this.auditLogService.log({
  actorAddress: patientId,
  action: 'GRANT_CHANGE',
  targetAddress: dto.granteeId,
  resourceType: 'AccessGrant',
  resourceId: updated.id,
  metadata: { recordIds: updated.recordIds, accessLevel: updated.accessLevel },
});
```

### Audit Module
**File:** [src/common/audit/audit.module.ts](src/common/audit/audit.module.ts)
- Includes audit interceptors for capturing request/response metadata
- Audit subscriber for event-driven logging
- Context guards and decorators for audit context injection

---

## 6. EXISTING DOWNLOAD/STREAM PATTERNS

### RecordDownloadService
**File:** [src/records/services/record-download.service.ts](src/records/services/record-download.service.ts)

```typescript
export interface DownloadResult {
  stream: Readable;
  contentType: string;
  filename: string;
}

@Injectable()
export class RecordDownloadService {
  async download(
    recordId: string,
    requesterId: string,
    ip: string,
    ua: string
  ): Promise<DownloadResult>

  // Process (7 steps):
  // 1. Load record from DB (throws NotFoundException if not found)
  // 2. Verify access grant using accessControl.verifyAccess()
  //    (throws ForbiddenException if no grant)
  // 3. Fetch encrypted bytes from IPFS (memory only, no disk write)
  // 4. Unpack envelope (extract IV, authTag, encryptedDek, dekVersion, ciphertext)
  // 5. Decrypt in-memory using encryptionService.decryptRecord()
  // 6. Create audit log before streaming (always written)
  // 7. Return Readable stream with plaintext buffer
  //    - Zero out buffer after streaming
  //    - stream.pipe(res) to client

  // Envelope Layout (stored in IPFS):
  // [iv:12][authTag:16][dekLen:4LE][encryptedDek:dekLen][verLen:2LE][dekVersion:verLen][ciphertext:rest]

  async fetchFromIpfs(cid: string): Promise<Buffer>
  // Streams all chunks from IPFS into single Buffer

  unpackEnvelope(buf: Buffer): EncryptedRecord
  // Extracts components from packed envelope format

  private inferContentType(recordType: string): string
  // Maps RecordType to MIME type
  // - imaging → 'application/dicom'
  // - lab_result → 'application/pdf'
  // - prescription → 'application/pdf'
  // - consultation → 'application/pdf'
}
```

### Controller Integration
**File:** [src/records/controllers/records.controller.ts](src/records/controllers/records.controller.ts#L148-L165)

```typescript
@Get(':id/download')
@UseGuards(JwtAuthGuard)
@ApiBearerAuth()
@ApiOperation({ summary: 'Download and decrypt a record file' })
async downloadRecord(
  @Param('id') id: string,
  @Req() req: any,
  @Res() res: Response
): Promise<void> {
  const requesterId: string = req.user?.userId ?? req.user?.id;
  const ip: string = req.ip ?? 'unknown';
  const ua: string = req.headers['user-agent'] ?? 'unknown';

  const { stream, contentType, filename } = await this.recordDownloadService.download(
    id,
    requesterId,
    ip,
    ua,
  );

  res.setHeader('Content-Type', contentType);
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.setHeader('Pragma', 'no-cache');

  stream.pipe(res);
}
```

### Key Response Headers
- `Content-Type`: Inferred from record type (e.g., `application/dicom`, `application/pdf`)
- `Content-Disposition`: `attachment; filename="record-{id}.bin"`
- `Cache-Control`: `no-store, no-cache, must-revalidate`
- `Pragma`: `no-cache`

### Memory Security Pattern
```typescript
// Plaintext is never written to disk:
// 1. Fetch from IPFS → memory buffer
// 2. Decrypt → memory buffer
// 3. Create Readable stream → holds reference to plaintext buffer
// 4. Pipe to response
// 5. setImmediate(() => plaintext.fill(0)) → wipe key material after stream reads
```

---

## SUMMARY TABLE

| Component | File Path | Key Classes/Methods | Parameter Types |
|-----------|-----------|-------------------|-----------------|
| **Records Module** | `src/records/records.module.ts` | RecordsModule, RecordsService, RecordsController | CreateRecordDto, PaginationQueryDto, SearchRecordsDto |
| **Records Controller** | `src/records/controllers/records.controller.ts` | RecordsController | Record, UUID, SearchResults |
| **Records Service** | `src/records/services/records.service.ts` | uploadRecord(), findAll(), search(), findOne() | Record, PaginationQueryDto, SearchRecordsDto |
| **Records Entity** | `src/records/entities/record.entity.ts` | Record, RecordType | string, UUID, enum |
| **Encryption Service** | `src/encryption/services/encryption.service.ts` | encryptRecord(), decryptRecord() | Buffer, patientId: string |
| **Key Management Service** | `src/encryption/services/key-management.service.ts` | wrapDek(), unwrapDek(), initializeTestKeks() | Buffer, patientId: string |
| **IPFS Service** | `src/records/services/ipfs.service.ts` | IpfsService.upload() | Buffer → CID: string |
| **IPFS with Breaker** | `src/records/services/ipfs-with-breaker.service.ts` | IpfsWithBreakerService.upload() | Buffer → CID: string |
| **Access Control Service** | `src/access-control/services/access-control.service.ts` | verifyAccess(), grantAccess(), revokeAccess() | AccessGrant, CreateAccessGrantDto |
| **Access Grant Entity** | `src/access-control/entities/access-grant.entity.ts` | AccessGrant, AccessLevel, GrantStatus | enum, UUID, string[] |
| **Audit Service** | `src/common/audit/audit.service.ts` | log(), logDataAccess(), logAuthenticationEvent() | AuditEventDto, SensitiveAuditEntry |
| **Audit Log Service** | `src/common/services/audit-log.service.ts` | create(), findByEntity(), log() | CreateAuditLogDto, SensitiveAuditEntry |
| **Audit Entity** | `src/common/audit/audit-log.entity.ts` | AuditLogEntity, AuditAction | enum, string, JSON |
| **Download Service** | `src/records/services/record-download.service.ts` | download(), fetchFromIpfs(), unpackEnvelope() | recordId, requesterId, DownloadResult |
| **Encryption Interfaces** | `src/encryption/interfaces/encrypted-record.interface.ts` | EncryptedRecord | Buffer (iv, ciphertext, authTag, encryptedDek) |

---

## INTEGRATION FLOW EXAMPLE: Record Download

```
Client Request
    ↓
RecordsController.downloadRecord()
    ↓
RecordDownloadService.download()
    ├─ 1. Load Record from DB
    ├─ 2. Verify Access: AccessControlService.verifyAccess()
    ├─ 3. Fetch from IPFS: IpfsService.fetchFromIpfs(cid)
    ├─ 4. Unpack: unpackEnvelope() → EncryptedRecord
    ├─ 5. Decrypt: EncryptionService.decryptRecord()
    │   └─ Calls: KeyManagementService.unwrapDek() [PRIVATE]
    ├─ 6. Audit Log: AuditService.logDataAccess()
    └─ 7. Stream: Readable.from(plaintext) → piped to res
         └─ Wiped: plaintext.fill(0) after streaming
    ↓
HTTP Response with headers:
    Content-Type: {inferred}
    Content-Disposition: attachment; filename=...
    Cache-Control: no-store, no-cache, must-revalidate
    Pragma: no-cache
```
