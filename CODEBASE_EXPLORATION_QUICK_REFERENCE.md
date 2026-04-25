# Healthy-Stellar Backend - Quick Reference Tables

## 1. MODULE COMPARISON MATRIX

| Feature | Records Module | Medical Records Module | Status |
|---------|---|---|---|
| **Storage Backend** | IPFS | Local Filesystem | Divergent |
| **Attachment Entity** | None (WIP) | MedicalAttachment ✅ | Partial |
| **Encryption** | AES-256-GCM (EncryptionService) ✅ | Plaintext LocalFS | Gap |
| **Upload Endpoint** | POST /records | POST /attachments/upload | Both Active |
| **File Size Limit** | 10 MB | 10 MB | Consistent |
| **Blockchain Anchor** | Stellar ✅ | None | Gap |
| **Multer Configured** | Yes ✅ | Yes ✅ | Consistent |
| **Role-Based Access** | JwtAuthGuard + RolesGuard ✅ | JwtAuthGuard only | Gap |
| **Audit Logging** | RecordEventStoreService ✅ | None visible | Gap |

---

## 2. RECORD/ATTACHMENT FIELDS BY ENTITY

### Record Entity (Records Module)
```
id (UUID) ✅
patientId (string) ✅
providerId (string, nullable) ✅
cid (IPFS, unique) ✅
stellarTxHash (unique, nullable) ✅
recordType (enum) ✅
description (text, nullable) ✅
isDeleted (boolean, soft-delete) ✅
deletedOnChainAt (timestamp, nullable) ✅
createdAt (auto) ✅
```
**Total Fields:** 10  
**Encryption Storage:** Separate (encrypted_dek, iv, auth_tag, dek_version)

### MedicalAttachment Entity (Medical Records Module)
```
id (UUID) ✅
medicalRecordId (UUID, FK) ✅
fileName (string, system-generated) ✅
originalFileName (string, user-provided) ✅
mimeType (string) ✅
fileSize (bigint) ✅
filePath (string, local filesystem) ✅
fileUrl (string, nullable) ✅
attachmentType (enum: IMAGE, DOCUMENT, LAB_REPORT, XRAY, SCAN, PRESCRIPTION, OTHER) ✅
description (text, nullable) ✅
uploadedBy (UUID) ✅
isActive (boolean, soft-delete) ✅
metadata (JSONB, nullable) ✅
createdAt (auto) ✅
updatedAt (auto) ✅
```
**Total Fields:** 15

---

## 3. ENCRYPTION SPECIFICATIONS

| Property | Value | Notes |
|----------|-------|-------|
| **Algorithm** | AES-256-GCM | NIST standard, provides confidentiality + integrity |
| **Key Type** | Data Encryption Key (DEK) | 256 bits (32 bytes) |
| **IV/Nonce** | 12 bytes (96 bits) | Unique per encryption, never reused |
| **Authentication Tag** | 16 bytes (128 bits) | Provides integrity verification |
| **Key Wrapping** | KEK (Key Encryption Key) | Patient-specific, managed by KMS |
| **Master Key** | From environment | ENCRYPTION_MASTER_KEY |
| **DEK Clearing** | buffer.fill(0) | After use, in success & error paths |
| **IV Uniqueness** | crypto.randomBytes(12) | Cryptographically secure random |
| **Storage Separation** | ✅ | Ciphertext on IPFS, DEK+IV+tag in PostgreSQL |

---

## 4. ROLE-BASED ACCESS CONTROL

### User Roles in System
```
ADMIN = 'admin'        // Full system access
PHYSICIAN = 'physician' // Healthcare provider (doctors, nurses, specialists)
PATIENT = 'patient'    // Patient/individual
```

### Guard Chain
```
JwtAuthGuard (extracts & verifies token)
    ↓
RolesGuard (checks @Roles() metadata)
    ↓
Access Allowed or ForbiddenException
```

### Common Endpoint Patterns
```
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles(UserRole.PHYSICIAN, UserRole.ADMIN)
→ Only physicians and admins can access
```

### Provider Authentication Flow
```
1. User provides credentials (email + password)
2. Auth service verifies credentials
3. JWT issued with role=PHYSICIAN (or ADMIN)
4. Token stored in request.user by JwtAuthGuard
5. RolesGuard checks user.role against @Roles() decorator
6. Endpoint executed if role matches, else ForbiddenException(403)
```

---

## 5. IPFS INTEGRATION CHECKLIST

### Configuration (Environment Variables)
- [ ] `IPFS_HOST` set (default: localhost)
- [ ] `IPFS_PORT` set (default: 5001)
- [ ] `IPFS_PROTOCOL` set (default: http)
- [ ] IPFS node running and accessible
- [ ] Network connectivity verified

### Service Initialization
- [ ] IpfsService instantiated with config
- [ ] ipfs-http-client library imported
- [ ] Connection established to IPFS API
- [ ] Health check passing

### Upload Flow
- [ ] Buffer prepared (encrypted record)
- [ ] ipfs.add(buffer) called
- [ ] CID returned from IPFS
- [ ] CID stored in Record.cid
- [ ] Ciphertext NOT stored in PostgreSQL

### Error Handling
- [ ] IpfsUploadException thrown on failure
- [ ] Circuit breaker prevents cascading failures
- [ ] Retry logic implemented (3 attempts, exponential backoff)
- [ ] Logging captured for debugging

---

## 6. FILE UPLOAD PATTERNS & CONSTRAINTS

### Size Limits

| Module | Limit | Enforcement | Config |
|--------|-------|-------------|--------|
| Records | 10 MB | FileInterceptor + Multer | records.module.ts |
| Medical Records | 10 MB | FileInterceptor + validateFile() | file-upload.service.ts |

### Allowed MIME Types (Medical Records Module)

```
✅ image/jpeg          - Photos, X-rays
✅ image/png           - Diagrams, charts
✅ image/gif           - Animations
✅ application/pdf     - Reports, documents
✅ application/msword  - .doc files
✅ application/vnd.openxmlformats-officedocument.wordprocessingml.document  - .docx
✅ text/plain          - Text notes
❌ application/exe     - Blocked (security)
❌ application/x-sh    - Blocked (security)
```

### No MIME Type Check (Records Module)
- Accepts any file type
- Assumes pre-encrypted by client
- Ciphertext is meaningless (can't determine real type)

---

## 7. DATABASE SCHEMA SUMMARY

### Key Tables

| Table | Purpose | Key Fields | Indexes |
|-------|---------|-----------|---------|
| `records` | IPFS-anchored medical records | id, cid, stellarTxHash, patientId | isDeleted, patientId |
| `medical_records` | Detailed patient records | id, patientId, status, recordType | (patientId, createdAt) |
| `medical_attachments` | File attachments to medical records | id, medicalRecordId, fileSize, attachmentType | (medicalRecordId, createdAt) |
| `encryption_metadata` | Storage for envelope encryption (separate) | encrypted_dek, iv, auth_tag, ipfs_cid | ipfs_cid, patient_id |
| `users` | User accounts | id, email, role | role, email |
| `access_grants` | Record sharing permissions | id, recordId, granteeId, permissions | (recordId, granteeId) |

---

## 8. ARCHITECTURE DECISION RECORDS (ADRs)

### ADR-1: Dual Module Approach
**Status:** Active (Legacy Medical + New Records)

**Records Module (New):**
- IPFS for data (immutable, distributed)
- Stellar for anchoring (blockchain timestamp)
- PostgreSQL for metadata only
- Encryption Service for AES-256-GCM

**Medical Records Module (Legacy):**
- Local filesystem for data
- PostgreSQL for metadata
- No encryption in transit/rest
- File-based operations

**Rationale:** Gradual migration path; legacy module continues for backward compatibility

---

### ADR-2: Envelope Encryption Pattern
**Status:** Approved for Records Module

**Design:**
1. Generate unique DEK per record
2. Encrypt plaintext with DEK
3. Wrap DEK with patient KEK
4. Store ciphertext separately from DEK

**Benefits:**
- DEK != KEK (separation of concerns)
- Easy re-key without reencryption
- Plaintext never stored
- Memory cleared after use

---

### ADR-3: File Storage Divergence
**Status:** Acknowledged Gap

**Current:**
- Records Module → IPFS (distributed, auditable)
- Medical Records Module → Local filesystem (legacy, simpler)

**Future:**
- Consolidate on IPFS + Encryption for all modules
- Migrate historical attachments incrementally

---

## 9. PROVIDER WORKFLOW EXAMPLES

### Provider Uploads Medical Record

```
1. Provider views Patient Dashboard
2. Provider clicks "Upload Record"
3. Provider selects encrypted file + metadata
4. Frontend sends POST /records
   - Authorization: Bearer <jwt_token_with_role=PHYSICIAN>
   - multipart/form-data (file, patientId, recordType, description)

5. Backend RecordsController
   - JwtAuthGuard extracts token → request.user.role = "PHYSICIAN"
   - RolesGuard checks if PHYSICIAN ∈ [required roles] → ✅ allowed
   - FileInterceptor processes file (10MB limit)
   - RecordsService.uploadRecord() invoked

6. Service Layer
   - IpfsService.upload(encryptedBuffer) → CID
   - StellarService.anchorCid(patientId, cid) → stellarTxHash
   - RecordRepository.save(record) → PostgreSQL
   - EventStore.append() → audit trail

7. Response 201 Created
   {
     "recordId": "uuid",
     "cid": "QmXxx...",
     "stellarTxHash": "0xABC..."
   }
```

### Provider Accesses Patient Records

```
1. Provider requests GET /records?patientId=patient-123
2. JwtAuthGuard validates token (role = PHYSICIAN)
3. RolesGuard passes (endpoint allows PHYSICIAN)
4. AccessControlService checks:
   - Does patient grant access to this provider? 
   - Which permission level (READ, READ_WRITE)?
5. Only matching records returned (access control enforced)
```

---

## 10. TESTING COVERAGE CHECKLIST

### Unit Tests
- [ ] EncryptionService (encrypt/decrypt, memory clearing)
- [ ] IpfsService (upload, error handling)
- [ ] FileUploadService (validation, filesystem operations)
- [ ] RolesGuard (role matching, exception throwing)

### Integration Tests
- [ ] POST /records flow (Multer → IPFS → Stellar → DB)
- [ ] POST /attachments/upload flow (validation → filesystem → DB)
- [ ] Access control (grant verification before retrieval)

### E2E Tests
- [ ] records.e2e-spec.ts (10MB file limit validation)
- [ ] access-control.e2e-spec.ts (provider role validation)
- [ ] auth-and-patient.e2e-spec.ts (provider registration)

### Load Tests
- [ ] record-upload.js scenario (concurrent uploads)
- [ ] Measure IPFS latency
- [ ] DB insert throughput

---

## 11. ENVIRONMENT CONFIGURATION TEMPLATE

```bash
# IPFS Configuration
IPFS_HOST=localhost
IPFS_PORT=5001
IPFS_PROTOCOL=http
IPFS_API_URL=http://localhost:5001
IPFS_URL=http://localhost:5001

# Stellar Configuration
STELLAR_NETWORK=PUBLIC  # or TESTNET
STELLAR_ACCOUNT_ID=xxx
STELLAR_SECRET_KEY=xxx
STELLAR_CONTRACT_ID=xxx

# Encryption Keys
ENCRYPTION_MASTER_KEY=<32+ character key>
ENCRYPTION_SALT=salt-value

# File Storage
UPLOAD_PATH=./storage/uploads

# JWT/Auth
JWT_SECRET=xxx
JWT_EXPIRY=3600s

# Database
DB_HOST=localhost
DB_PORT=5432
DB_NAME=healthy_stellar
DB_USER=postgres
DB_PASSWORD=xxx
```

---

## 12. CRITICAL PATH FOR NEW FEATURE

To implement: **POST /records/:id/attachments** with proper encryption, IPFS, and provider role validation:

**Order of Implementation:**
1. ✅ Create RecordAttachment entity & repository
2. ✅ Add @UseGuards(JwtAuthGuard, RolesGuard) + @Roles(UserRole.PHYSICIAN, UserRole.ADMIN)
3. ✅ Extract FileInterceptor('file') with 10 MB limit
4. ✅ Validate MIME types (whitelist approach)
5. ✅ Call EncryptionService.encryptRecord(file.buffer, patientId)
6. ✅ Call IpfsService.upload(encryptedBuffer) → CID
7. ✅ Call AccessControlService.canWrite(userId, recordId)
8. ✅ Save RecordAttachment (cid, encrypted_dek, iv, auth_tag, uploaded_by)
9. ✅ Append audit event
10. ✅ Return 201 with attachment details

**Dependencies Already Available:**
- JwtAuthGuard ✅
- RolesGuard ✅
- FileInterceptor ✅
- EncryptionService ✅
- IpfsService ✅
- AccessControlService ✅
- AuditLogService ✅

