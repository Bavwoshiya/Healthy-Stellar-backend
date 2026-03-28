# Healthy-Stellar Backend - Codebase Exploration Findings

## Executive Summary

This analysis covers the current implementation patterns for medical record management, file uploads, encryption, and IPFS integration in the Healthy-Stellar backend. Two parallel record management systems exist: **Records Module** (newer, IPFS-centric) and **Medical Records Module** (established, file-based).

---

## 1. RECORDS MODULE STRUCTURE

### Location
`src/records/`

### Controllers
- **[RecordsController](src/records/controllers/records.controller.ts)** - Main REST API endpoints
  - `POST /records` - Upload encrypted medical records
  - `GET /records` (deprecated) - List records with pagination
  - `GET /records/search` - Search records with filters
  - `GET /records/:id` - Get specific record
  - `GET /records/:id/download` - Download record (decrypted)
  - `GET /records/related/:id` - Get related records

### Entities

#### Record Entity
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

**Key Fields:**
- `id` (UUID) - Primary identifier
- `patientId` - Patient reference
- `providerId` - Healthcare provider reference (nullable)
- `cid` - IPFS content identifier (ciphertext stored there)
- `stellarTxHash` - Blockchain anchor for integrity verification
- `recordType` - Enum (MEDICAL_REPORT, LAB_RESULT, PRESCRIPTION, IMAGING, CONSULTATION)
- `isDeleted` - Soft-delete flag (mirrors on-chain record_deleted event)
- `deletedOnChainAt` - Timestamp of on-chain deletion

### Services

#### RecordsService
**File:** [src/records/services/records.service.ts](src/records/services/records.service.ts)

**Methods:**
- `uploadRecord(dto: CreateRecordDto, encryptedBuffer: Buffer)` - Upload flow
  1. Calls `IpfsService.upload(encryptedBuffer)` → returns CID
  2. Calls `StellarService.anchorCid(patientId, cid)` → returns stellarTxHash
  3. Persists to database via `recordRepository.save()`
  4. Appends event to event store for audit trail

- `findAll(query: PaginationQueryDto)` - List records with pagination
- `search(dto: SearchRecordsDto)` - Full-text search with filters
- `findOne(id: string)` - Get single record with access control check

#### IpfsService
**File:** [src/records/services/ipfs.service.ts](src/records/services/ipfs.service.ts)

```typescript
@Injectable()
export class IpfsService {
  async upload(buffer: Buffer): Promise<string> {
    // 1. Upload encrypted buffer to IPFS
    // 2. Return Content Identifier (CID)
    // 3. Includes distributed tracing events
  }
}
```

**Configuration:**
- IPFS Host: From env `IPFS_HOST` (default: localhost)
- IPFS Port: From env `IPFS_PORT` (default: 5001)
- IPFS Protocol: From env `IPFS_PROTOCOL` (default: http)

#### IpfsWithBreakerService
**File:** [src/records/services/ipfs-with-breaker.service.ts](src/records/services/ipfs-with-breaker.service.ts)

Wraps `IpfsService` with circuit breaker pattern to prevent cascading failures.

#### RecordDownloadService
**File:** [src/records/services/record-download.service.ts](src/records/services/record-download.service.ts)

Handles decrypted download flow:
1. Fetch from IPFS (ciphertext)
2. Retrieve encrypted DEK + IV + auth tag from PostgreSQL
3. Call `EncryptionService.decryptRecord()`
4. Stream plaintext to response
5. Clear sensitive data from memory

### Module Configuration
**File:** [src/records/records.module.ts](src/records/records.module.ts)

```typescript
@Module({
  imports: [
    TypeOrmModule.forFeature([Record, RecordEvent, RecordSnapshot, RecordTemplate]),
    MulterModule.register({ limits: { fileSize: 10 * 1024 * 1024 } }),  // 10MB limit
    EventEmitterModule.forRoot(),
    CircuitBreakerModule,
    AccessControlModule,
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
})
```

---

## 2. FILE UPLOAD PATTERNS

### Current Upload Endpoints

#### Records Module (IPFS-Centric)
**Endpoint:** `POST /records`

```typescript
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
)
```

**Request DTO:** [CreateRecordDto](src/records/dto/create-record.dto.ts)
```typescript
export class CreateRecordDto {
  @IsString()
  patientId: string;

  @IsEnum(RecordType)
  recordType: RecordType;

  @IsOptional()
  @IsString()
  description?: string;
}
```

**Request Format:** `multipart/form-data`
- `file` (binary, required) - Encrypted record blob
- `patientId` (string, required)
- `recordType` (enum, required)
- `description` (string, optional)

**Response:**
```json
{
  "recordId": "uuid",
  "cid": "QmXxx...",
  "stellarTxHash": "abc123..."
}
```

#### Medical Records Module (File-Based)
**Endpoint:** `POST /attachments/upload`

```typescript
@Post('upload')
@UseInterceptors(FileInterceptor('file'))
async uploadFile(
  @UploadedFile() file: Express.Multer.File,
  @Query('recordId') recordId: string,
  @Query('attachmentType') attachmentType: AttachmentType,
  @Query('description') description?: string,
  @Req() req?: any
)
```

**File Size Limits:**
- Records Module: 10 MB
- Medical Records Module: 10 MB (also enforced in `FileUploadService.validateFile()`)

**Multer Configuration:**
- Registered in `records.module.ts`: `limits: { fileSize: 10 * 1024 * 1024 }`
- Interceptor on each endpoint for additional limits

---

## 3. ENCRYPTION INTEGRATION

### Encryption Architecture

**Location:** `src/encryption/`

#### EncryptionService
**File:** [src/encryption/services/encryption.service.ts](src/encryption/services/encryption.service.ts)

**Envelope Encryption Pattern:**
```
Medical Record (Plaintext)
         ↓
   [Generate DEK] ----→ DEK (32 bytes, in memory)
         ↓
   [Encrypt with DEK] → Ciphertext
         ↓                  ↓
   [Wrap DEK with KEK]  [Store on IPFS]
         ↓                  ↓
   Encrypted DEK      Returns CID
         ↓
   Store in PostgreSQL (encrypted_dek, iv, auth_tag, dek_version, ipfs_cid, patient_id)
```

#### Key Methods

**encryptRecord(payload: Buffer, patientId: string): Promise<EncryptedRecord>**
1. Generate unique 32-byte DEK using `crypto.randomBytes(32)`
2. Generate unique 12-byte IV using `crypto.randomBytes(12)`
3. Create AES-256-GCM cipher with DEK and IV
4. Encrypt payload
5. Extract 16-byte authentication tag
6. Call `kms.wrapDek()` to encrypt DEK with patient's KEK
7. Clear plaintext DEK from memory
8. Return `EncryptedRecord` structure

**decryptRecord(encryptedRecord: EncryptedRecord, patientId: string): Promise<Buffer>**
1. Validate all fields present in `EncryptedRecord`
2. Call `kms.unwrapDek()` to decrypt DEK
3. Create AES-256-GCM decipher
4. Set authentication tag
5. Decrypt ciphertext
6. Verify authentication tag (throws on failure)
7. Clear plaintext DEK from memory
8. Return decrypted payload

#### Encryption Specifications
- **Algorithm:** AES-256-GCM (Galois/Counter Mode)
- **Key Size:** 256 bits (32 bytes)
- **IV Size:** 12 bytes (96 bits)
- **Auth Tag Size:** 16 bytes (128 bits)
- **Key Uniqueness:** Each record has unique DEK + IV
- **Memory Clearing:** DEKs wiped with `buffer.fill(0)` after use

#### KeyManagementService
**File:** [src/encryption/services/key-management.service.ts](src/encryption/services/key-management.service.ts)

Intentionally NOT exported from module to enforce security boundaries.

**Methods:**
- `wrapDek(dek: Buffer, patientId: string): Promise<Buffer>` - Encrypt DEK with patient's KEK
- `unwrapDek(encryptedDek: Buffer, patientId: string): Promise<Buffer>` - Decrypt DEK with patient's KEK
- `initializePatientKek(patientId: string)` - Initialize key encryption key for patient

---

## 4. IPFS INTEGRATION

### Multiple IPFS Service Implementations

| File | Purpose | Notes |
|------|---------|-------|
| `src/records/services/ipfs.service.ts` | Main upload service | Uses `ipfs-http-client` library |
| `src/records/services/ipfs-with-breaker.service.ts` | Circuit breaker wrapper | Prevents cascading failures |
| `src/medical-records/services/ipfs.service.ts` | Medical records IPFS | Alternative implementation |
| `src/stellar/services/ipfs.service.ts` | Stellar integration | Fetch + upload operations |

### Primary IPFS Service Flow

**File:** [src/records/services/ipfs.service.ts](src/records/services/ipfs.service.ts)

```typescript
@Injectable()
export class IpfsService {
  private ipfs: any;

  constructor(private readonly tracingService: TracingService) {
    this.ipfs = create({
      host: process.env.IPFS_HOST || 'localhost',
      port: parseInt(process.env.IPFS_PORT || '5001'),
      protocol: process.env.IPFS_PROTOCOL || 'http',
    });
  }

  async upload(buffer: Buffer): Promise<string> {
    // 1. Add buffer to IPFS
    // 2. Return CID (Content Identifier)
    // 3. Include distributed tracing events
    return cid;
  }
}
```

### Environment Configuration

```
IPFS_HOST=localhost (or kubo container hostname)
IPFS_PORT=5001 (default API port)
IPFS_PROTOCOL=http
IPFS_URL=http://localhost:5001 (for fetch operations)
IPFS_API_URL=http://localhost:5001 (for form-based add)
```

### IPFS Upload Flow

```
1. Encrypted Buffer (from client)
   ↓
2. RecordsService.uploadRecord()
   ↓
3. IpfsService.upload(encryptedBuffer)
   ├─ Calls ipfs.add(buffer)
   ├─ Returns { path: "QmXxxx..." } = CID
   └─ Distributed tracing event logged
   ↓
4. CID stored in Record.cid
5. Ciphertext never stored locally or in DB
6. Only metadata (encrypted DEK, IV, auth tag) stored in PostgreSQL
```

### Health Check
**Endpoint:** Health check includes IPFS status via `IpfsHealthIndicator`

---

## 5. RECORD ATTACHMENT ENTITY

### MedicalAttachment Entity (Medical Records Module)

**File:** [src/medical-records/entities/medical-attachment.entity.ts](src/medical-records/entities/medical-attachment.entity.ts)

```typescript
@Entity('medical_attachments')
@Index(['medicalRecordId', 'createdAt'])
export class MedicalAttachment {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  @Index()
  medicalRecordId: string;

  @ManyToOne(() => MedicalRecord, (record) => record.attachments, {
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'medicalRecordId' })
  medicalRecord: MedicalRecord;

  @Column({ type: 'varchar', length: 255 })
  fileName: string;

  @Column({ type: 'varchar', length: 255 })
  originalFileName: string;

  @Column({ type: 'varchar', length: 100 })
  mimeType: string;

  @Column({ type: 'bigint' })
  fileSize: number;

  @Column({ type: 'varchar', length: 500 })
  filePath: string;

  @Column({ type: 'varchar', length: 500, nullable: true })
  fileUrl: string;

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
```

### AttachmentType Enum
```typescript
export enum AttachmentType {
  IMAGE = 'image',
  DOCUMENT = 'document',
  LAB_REPORT = 'lab_report',
  XRAY = 'xray',
  SCAN = 'scan',
  PRESCRIPTION = 'prescription',
  OTHER = 'other',
}
```

### Field Details

| Field | Type | Nullable | Purpose |
|-------|------|----------|---------|
| `id` | UUID | No | Primary key |
| `medicalRecordId` | UUID | No | Foreign key to MedicalRecord |
| `fileName` | VARCHAR(255) | No | System-generated name (UUID-based) |
| `originalFileName` | VARCHAR(255) | No | Client-provided original name |
| `mimeType` | VARCHAR(100) | No | Content type (e.g., image/jpeg) |
| `fileSize` | BIGINT | No | File size in bytes |
| `filePath` | VARCHAR(500) | No | Local filesystem path |
| `fileUrl` | VARCHAR(500) | Yes | Public/download URL |
| `attachmentType` | ENUM | No | Classification of attachment |
| `description` | TEXT | Yes | User-provided metadata |
| `uploadedBy` | UUID | No | User ID who uploaded |
| `isActive` | BOOLEAN | No | Soft-delete flag |
| `metadata` | JSONB | Yes | Arbitrary metadata storage |
| `createdAt` | TIMESTAMP | No | Creation timestamp |
| `updatedAt` | TIMESTAMP | No | Last update timestamp |

### Relationship with MedicalRecord

**MedicalRecord Entity** [src/medical-records/entities/medical-record.entity.ts](src/medical-records/entities/medical-record.entity.ts):
```typescript
@OneToMany(() => MedicalAttachment, (attachment) => attachment.medicalRecord, {
  cascade: true,
})
attachments: MedicalAttachment[];
```

**Database Relationship:**
- One MedicalRecord → Many MedicalAttachments
- Cascade delete enabled (deleting record deletes attachments)
- Index on (medicalRecordId, createdAt) for efficient querying

---

## 6. PROVIDER ROLE AUTHENTICATION

### User Roles

**File:** [src/auth/entities/user.entity.ts](src/auth/entities/user.entity.ts)

```typescript
export enum UserRole {
  ADMIN = 'admin',
  PHYSICIAN = 'physician',  // Healthcare provider (doctors, nurses, etc.)
  PATIENT = 'patient',
}
```

**Note:** The system uses `PHYSICIAN` role for healthcare providers, not a separate `PROVIDER` role.

### JWT Payload Structure
```typescript
interface JwtPayload {
  sub: string;        // User ID
  email: string;
  role: UserRole;     // One of ADMIN, PHYSICIAN, PATIENT
  sessionId: string;
  iat: number;
  exp: number;
}
```

### Role Validation Guards

#### JwtAuthGuard
**File:** [src/auth/guards/jwt-auth.guard.ts](src/auth/guards/jwt-auth.guard.ts)

**Flow:**
1. Extract JWT from `Authorization: Bearer <token>` header
2. Verify token signature
3. Check session validity
4. Update session activity
5. Attach user payload to request

```typescript
@Injectable()
export class JwtAuthGuard implements CanActivate {
  async canActivate(context: ExecutionContext): Promise<boolean> {
    // 1. Check if route is @Public() decorated
    // 2. Extract and verify token
    // 3. Validate session
    // 4. Attach request.user = JwtPayload
    // 5. Return true if valid
  }
}
```

#### RolesGuard
**File:** [src/auth/guards/roles.guard.ts](src/auth/guards/roles.guard.ts)

**Flow:**
1. Extract user from request
2. Get required roles from `@Roles()` decorator metadata
3. Check if user's role matches required roles
4. Throw `ForbiddenException` if no match

```typescript
@Injectable()
export class RolesGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest();
    const user: JwtPayload = request.user;
    const requiredRoles: UserRole[] = Reflect.getMetadata('roles', context.getHandler()) || [];

    if (requiredRoles.length === 0) {
      return true; // No specific roles required
    }

    const hasRole = requiredRoles.includes(user.role);
    if (!hasRole) {
      throw new ForbiddenException(`Access denied. Required roles: ${requiredRoles.join(', ')}`);
    }

    return true;
  }
}
```

### Guard Usage Patterns

**Admin-only endpoint:**
```typescript
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(UserRole.ADMIN)
@Get('/admin/analytics')
async getAnalytics() { }
```

**Physician or Admin endpoint:**
```typescript
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(UserRole.PHYSICIAN, UserRole.ADMIN)
@Post('/access-grants')
async grantAccess() { }
```

**Patient endpoint:**
```typescript
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(UserRole.PATIENT)
@Get('/my-records')
async getMyRecords() { }
```

### Medical RBAC Module
**File:** [src/roles/medical-rbac.guard.ts](src/roles/medical-rbac.guard.ts)

Additional RBAC layer using `@MedicalRoles()` decorator and `MedicalRbacGuard` for finer-grained medical roles.

### Current Authorization Patterns

| Endpoint | Required Role | Guard |
|----------|---------------|-------|
| `POST /records` | PHYSICIAN, ADMIN | JwtAuthGuard, RolesGuard |
| `GET /records` | PHYSICIAN, PATIENT, ADMIN | JwtAuthGuard |
| `POST /access-grants` | PHYSICIAN, ADMIN | JwtAuthGuard, RolesGuard |
| `GET /access-grants` | PATIENT | JwtAuthGuard, RolesGuard |
| `POST /attachments/upload` | PHYSICIAN, ADMIN | JwtAuthGuard |
| `POST /admin/analytics` | ADMIN | JwtAuthGuard, RolesGuard |

---

## 7. DATABASE SCHEMA

### Records Table

```sql
CREATE TABLE records (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  patientId VARCHAR NOT NULL,
  providerId VARCHAR NULLABLE,
  cid VARCHAR NOT NULL UNIQUE,
  stellarTxHash VARCHAR NULLABLE UNIQUE,
  recordType VARCHAR NOT NULL,
  description VARCHAR NULLABLE,
  isDeleted BOOLEAN DEFAULT false,
  deletedOnChainAt TIMESTAMP WITH TIME ZONE NULLABLE,
  createdAt TIMESTAMP DEFAULT NOW(),
  
  INDEX idx_records_deleted (isDeleted),
  INDEX idx_records_patient_id (patientId),
  INDEX idx_records_provider_id (providerId)
);
```

### Medical Records Table

```sql
CREATE TABLE medical_records (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  patientId UUID NOT NULL,
  providerId UUID NULLABLE,
  status VARCHAR {ACTIVE, ARCHIVED, DELETED},
  recordType VARCHAR {CONSULTATION, DIAGNOSIS, TREATMENT, LAB_RESULT, IMAGING, PRESCRIPTION, SURGERY, EMERGENCY, OTHER},
  stellarTxHash VARCHAR NULLABLE,
  metadata JSONB NULLABLE,
  version INT DEFAULT 1,
  createdAt TIMESTAMP DEFAULT NOW(),
  updatedAt TIMESTAMP DEFAULT NOW(),
  updatedBy UUID NULLABLE,
  
  INDEX idx_medical_records_patient_date (patientId, createdAt),
  INDEX idx_medical_records_status_type (status, recordType)
);
```

### Medical Attachments Table

```sql
CREATE TABLE medical_attachments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  medicalRecordId UUID NOT NULL REFERENCES medical_records(id) ON DELETE CASCADE,
  fileName VARCHAR(255) NOT NULL,
  originalFileName VARCHAR(255) NOT NULL,
  mimeType VARCHAR(100) NOT NULL,
  fileSize BIGINT NOT NULL,
  filePath VARCHAR(500) NOT NULL,
  fileUrl VARCHAR(500) NULLABLE,
  attachmentType VARCHAR {IMAGE, DOCUMENT, LAB_REPORT, XRAY, SCAN, PRESCRIPTION, OTHER},
  description TEXT NULLABLE,
  uploadedBy UUID NOT NULL,
  isActive BOOLEAN DEFAULT true,
  metadata JSONB NULLABLE,
  createdAt TIMESTAMP DEFAULT NOW(),
  updatedAt TIMESTAMP DEFAULT NOW(),
  
  INDEX idx_medical_attachments_record_date (medicalRecordId, createdAt)
);
```

### Encryption Storage (PostgreSQL)

Additional columns or separate table to store envelope encryption components:
```sql
-- Stored WITH encrypted Records or in separate table
encrypted_dek VARCHAR(500) NOT NULL,     -- Wrapped with patient KEK
iv VARCHAR(50) NOT NULL,                 -- Initialization vector
auth_tag VARCHAR(50) NOT NULL,           -- Authentication tag
dek_version VARCHAR(20) NOT NULL,        -- KEK version identifier
ipfs_cid VARCHAR(500) NOT NULL,          -- References ciphertext on IPFS
patient_id UUID NOT NULL,                -- For key derivation
```

### Key Indexes

| Table | Index | Purpose |
|-------|-------|---------|
| records | isDeleted | Soft-delete queries |
| records | patientId | Patient record lookup |
| medical_records | (patientId, createdAt) | Pagination by patient |
| medical_attachments | (medicalRecordId, createdAt) | Attachment retrieval |

---

## 8. EXISTING UPLOAD ENDPOINTS

### Records Module (IPFS-Based)

#### POST /records
**Purpose:** Upload encrypted medical record to IPFS and anchor on Stellar

**Implementation:** [src/records/controllers/records.controller.ts#L49-L64](src/records/controllers/records.controller.ts)

```typescript
@Post()
@UseInterceptors(
  FileInterceptor('file', {
    limits: { fileSize: 10 * 1024 * 1024 }
  })
)
async uploadRecord(
  @Body() dto: CreateRecordDto,
  @UploadedFile() file: Express.Multer.File
)
```

**Request:**
```bash
curl -X POST http://localhost:3000/records \
  -H "Authorization: Bearer <token>" \
  -F "file=@encrypted-record.bin" \
  -F "patientId=patient-123" \
  -F "recordType=MEDICAL_REPORT" \
  -F "description=Annual checkup"
```

**Response (201 Created):**
```json
{
  "recordId": "123e4567-e89b-12d3-a456-426614174000",
  "cid": "QmXxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "stellarTxHash": "xxxxxxxxxxxxxxxxxxxxxxxx"
}
```

**Validations:**
- File required (no null allowed)
- File size: max 10 MB
- patientId: required string
- recordType: required enum (MEDICAL_REPORT, LAB_RESULT, PRESCRIPTION, IMAGING, CONSULTATION)
- description: optional string

**Error Responses:**
```json
// Missing file
{ "statusCode": 400, "message": "Encrypted record file is required" }

// File too large
{ "statusCode": 413, "message": "Payload too large" }

// Invalid recordType
{ "statusCode": 400, "message": "Invalid recordType enum" }
```

### Medical Records Module (File-Based)

#### POST /attachments/upload
**Purpose:** Upload file attachment to medical record

**Implementation:** [src/medical-records/controllers/file-upload.controller.ts#L25-L63](src/medical-records/controllers/file-upload.controller.ts)

```typescript
@Post('upload')
@UseInterceptors(FileInterceptor('file'))
async uploadFile(
  @UploadedFile() file: Express.Multer.File,
  @Query('recordId') recordId: string,
  @Query('attachmentType') attachmentType: AttachmentType,
  @Query('description') description?: string,
  @Req() req?: any
)
```

**Request:**
```bash
curl -X POST "http://localhost:3000/attachments/upload?recordId=record-123&attachmentType=IMAGE&description=Patient%20photo" \
  -H "Authorization: Bearer <token>" \
  -F "file=@patient-photo.jpg"
```

**Response (201 Created):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "medicalRecordId": "record-123",
  "fileName": "550e8400-e29b-41d4-a716.jpg",
  "originalFileName": "patient-photo.jpg",
  "mimeType": "image/jpeg",
  "fileSize": 245678,
  "filePath": "/storage/uploads/550e8400-e29b-41d4-a716.jpg",
  "fileUrl": "/uploads/550e8400-e29b-41d4-a716.jpg",
  "attachmentType": "IMAGE",
  "description": "Patient photo",
  "uploadedBy": "user-456",
  "createdAt": "2026-03-28T10:00:00Z",
  "updatedAt": "2026-03-28T10:00:00Z"
}
```

**Validations:**
- File required (Express.Multer.File)
- File size: max 10 MB
- MIME type whitelist: image/jpeg, image/png, image/gif, application/pdf, application/msword, application/vnd.openxmlformats-officedocument.wordprocessingml.document, text/plain
- recordId: required string (medical record must exist)
- attachmentType: required enum (IMAGE, DOCUMENT, LAB_REPORT, XRAY, SCAN, PRESCRIPTION, OTHER)
- description: optional string

**Error Responses:**
```json
// File type not allowed
{ "statusCode": 400, "message": "File type image/bmp is not allowed" }

// File size exceeds limit
{ "statusCode": 400, "message": "File size exceeds maximum allowed size (10MB)" }

// Medical record not found
{ "statusCode": 404, "message": "Medical record with ID record-123 not found" }
```

**File Storage:**
- Location: `./storage/uploads/` (or `process.env.UPLOAD_PATH`)
- Naming: UUID-based with original extension preserved
- Files stored on local filesystem (not IPFS)

### Other Upload Implementations

#### GraphQL Upload Resolver
**File:** [src/graphql-queries/resolvers/mutation.resolver.ts#L67-L105](src/graphql-queries/resolvers/mutation.resolver.ts)

```typescript
@Mutation(() => UploadRecordPayload)
@UseGuards(GqlAuthGuard)
async uploadRecord(
  @Args('input', { type: () => UploadRecordInput })
  input: UploadRecordInput,
  @CurrentUser() user: GqlUser
): Promise<UploadRecordPayload>
```

Includes:
- Idempotency key support (caching to prevent duplicate uploads)
- Background queue dispatch for large files
- Job status tracking with estimated completion time

---

## IMPLEMENTATION STATUS SUMMARY

### ✅ Currently Implemented

| Component | Status | Location | Notes |
|-----------|--------|----------|-------|
| Records Module | ✅ Complete | `src/records/` | Production-ready IPFS + Stellar integration |
| Medical Records Module | ✅ Complete | `src/medical-records/` | Legacy file-based system, deprecated for new records |
| MedicalAttachment Entity | ✅ Complete | `src/medical-records/entities/` | Full schema with 14 fields, cascade delete |
| File Upload Controllers | ✅ Complete | Both modules | Multer-based file handling |
| Encryption Service | ✅ Complete | `src/encryption/` | AES-256-GCM envelope encryption |
| IPFS Integration | ✅ Complete | `src/records/services/` | Multiple implementations with circuit breaker |
| Role-Based Access Control | ✅ Complete | `src/auth/guards/` | JwtAuthGuard + RolesGuard pattern |
| Database Schema | ✅ Complete | PostgreSQL | Proper indexes and relationships |

### ⚠️ Gaps & Areas to Enhance

| Area | Gap | Recommendation |
|------|-----|-----------------|
| **Attachment Encryption** | Medical attachments stored in plaintext on filesystem | Consider encrypting medical attachments before storage |
| **Attachment IPFS Migration** | Medical attachments use local FS, not IPFS | Could migrate to IPFS for distributed redundancy |
| **RecordAttachment for IPFS Records** | No corresponding attachment table for `records` table | May need `record_attachments` table for IPFS-based records |
| **Provider Role Specificity** | Uses `PHYSICIAN` role for all providers | Could add separate provider credentials/qualifications tracking |
| **File Validation** | Basic MIME type whitelist | Could add more sophisticated file validation (magic bytes, virus scanning) |
| **Audit Logging** | Events logged for records, not attachments | Should audit file upload/delete operations |
| **Rate Limiting** | No per-user upload rate limits visible | Could add rate limiting to prevent abuse |
| **Virus Scanning** | No file virus scanning before storage | Should integrate ClamAV or similar for compliance |

---

## CODE LOCATION QUICK REFERENCE

### Core Services
- Records: `src/records/services/records.service.ts`
- IPFS: `src/records/services/ipfs.service.ts`
- Encryption: `src/encryption/services/encryption.service.ts`
- File Upload: `src/medical-records/services/file-upload.service.ts`

### Controllers
- Records: `src/records/controllers/records.controller.ts`
- File Attachments: `src/medical-records/controllers/file-upload.controller.ts`

### Entities
- Record: `src/records/entities/record.entity.ts`
- MedicalAttachment: `src/medical-records/entities/medical-attachment.entity.ts`
- MedicalRecord: `src/medical-records/entities/medical-record.entity.ts`

### DTOs & Types
- CreateRecordDto: `src/records/dto/create-record.dto.ts`
- UserRole: `src/auth/entities/user.entity.ts`
- AttachmentType: `src/medical-records/entities/medical-attachment.entity.ts`

### Guards & Middleware
- JwtAuthGuard: `src/auth/guards/jwt-auth.guard.ts`
- RolesGuard: `src/auth/guards/roles.guard.ts`

### Configuration
- Records Module: `src/records/records.module.ts`
- Medical Records Module: `src/medical-records/medical-records.module.ts`
- Encryption Module: `src/encryption/encryption.module.ts`

---

## RECOMMENDATIONS FOR ATTACHMENT UPLOAD FEATURE

For implementing a new record attachment endpoint (POST /records/:id/attachments):

1. **Create RecordAttachment Entity** - Mirror MedicalAttachment but reference Record instead
2. **Implement Encryption** - Use EncryptionService to encrypt attachments before IPFS storage
3. **Extend Records Module** - Add attachment endpoints to records controller
4. **Preserve Provider Links** - Track `uploadedBy` field with PHYSICIAN role validation
5. **Distribute Storage** - Store encrypted attachment ciphertext on IPFS, metadata in PostgreSQL
6. **Implement Access Control** - Use AccessControlService to verify upload permissions
7. **Add Audit Trail** - Log attachment operations via AuditLogService
8. **Security Hardening** - Add virus scanning, file type validation, rate limiting

---

## APPENDIX: Testing References

### E2E Tests
- Records upload test: `test/integration/records.e2e-spec.ts`
- Access control tests: `test/access-control.e2e-spec.ts`
- Auth tests: `test/auth-and-patient.e2e-spec.ts`

### Load Tests
- Record upload scenario: `load-tests/scenarios/record-upload.js`
- k6 configuration: `load-tests/config/config.js`

### Unit Test Patterns
- RecordsService: `src/records/services/records.service.spec.ts`
- EncryptionService: `src/encryption/services/encryption.service*.spec.ts`
- FileUploadService: Patterns in medical-records module

