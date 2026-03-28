# Comprehensive E2E Test Suite for Healthy-Stellar Backend

## Overview

This document describes the complete end-to-end (E2E) test suite implementation for the Healthy-Stellar backend application (Issue #226). The test suite comprises **4 comprehensive test files** covering all critical user journeys, authentication flows, access control operations, medical record CRUD operations, and role-based authorization.

## Test Files

### 1. [auth-and-patient.e2e-spec.ts](auth-and-patient.e2e-spec.ts) - Authentication & Patient Management
**Purpose**: Comprehensive testing of user registration, authentication, and patient profile management workflows.

**Test Coverage**:
- ✅ **Patient Registration** (POST /auth/register)
  - Successful registration with all required fields
  - Associated patient entity creation with auto-generated MRN
  - Duplicate email rejection
  - Invalid email format rejection
  - Weak password rejection
  - Missing required fields validation

- ✅ **Healthcare Provider Registration** (POST /auth/register/staff)
  - Physician registration
  - Nurse registration
  - Role-based staff registration with NPI and license number
  - Invalid role rejection

- ✅ **Authentication** (POST /auth/login)
  - Login with valid credentials
  - Invalid password rejection
  - Non-existent email rejection
  - lastLoginAt timestamp updated on successful login

- ✅ **Token Refresh** (POST /auth/refresh)
  - Access token refresh with valid refresh token
  - Invalid token rejection

- ✅ **Current User Profile** (GET /auth/me)
  - Retrieve authenticated user profile
  - Token requirement validation
  - Invalid token rejection

- ✅ **Password Management** (POST /auth/change-password)
  - Password change with valid old password
  - Wrong old password rejection
  - New password validation on subsequent login
  - Old password invalidation after change

- ✅ **Session Management** (POST /auth/logout)
  - Successful logout
  - Token invalidation after logout

- ✅ **Patient Profile Retrieval** (GET /patients/:id)
  - Own profile retrieval
  - Unauthorized access to other patient records (403)

- ✅ **Admin Patient Listing** (GET /patients/admin/all)
  - Admin access to all patients
  - Non-admin rejection (403)

- ✅ **Integration Tests**
  - Full patient registration and login workflow
  - Provider registration workflow

**Test Count**: ~20 test cases

---

### 2. [access-control.e2e-spec.ts](access-control.e2e-spec.ts) - Access Control & Privacy
**Purpose**: Complete testing of the access grant/revoke workflow, privacy controls, and multi-party access scenarios.

**Test Coverage**:
- ✅ **Grant Access** (POST /access/grant)
  - Grant READ access to provider
  - Grant READ_WRITE access
  - Set expiration dates
  - Mark emergency access with reasons
  - Non-patient rejection (403)
  - Non-existent records rejection
  - Database persistence verification

- ✅ **List Patient Grants** (GET /access/grants)
  - List all active grants for patient
  - Prevent cross-patient grant viewing
  - Authentication requirement

- ✅ **List Provider Received Grants** (GET /access/received)
  - List grants received by provider
  - Include record details in response

- ✅ **Revoke Access** (DELETE /access/grant/:grantId)
  - Revoke access by patient
  - Include revocation reasons
  - Prevent provider from revoking
  - Authentication requirement
  - Database status update to REVOKED
  - Prevent duplicate revocation

- ✅ **Integration Tests**
  - Complete grant → verify → revoke workflow
  - Multiple concurrent grants to different providers
  - Expired grant enforcement
  - Self-grant prevention (security edge case)

**Test Count**: ~18 test cases

---

### 3. [medical-records.e2e-spec.ts](medical-records.e2e-spec.ts) - Medical Record CRUD Operations
**Purpose**: Comprehensive testing of medical record creation, retrieval, updating, and deletion with access control enforcement.

**Test Coverage**:
- ✅ **Create Records** (POST /records)
  - Create new medical records with metadata
  - Stellar tx hash generation
  - Database persistence
  - Authentication requirement
  - Provider prevention from creating patient records
  - Required field validation
  - Multiple records from same patient

- ✅ **Retrieve Records** (GET /records/:id)
  - Retrieve own records as patient
  - IPFS content fetching
  - Non-existent record (404) handling
  - Cross-patient access rejection (403)
  - Provider access with valid grant
  - Access check caching
  - Authentication requirement

- ✅ **List Records** (GET /records)
  - List all patient records
  - Pagination support
  - Cross-patient data isolation
  - Authentication requirement

- ✅ **Update Records** (PUT /records/:id)
  - Update record metadata by patient
  - Database update persistence
  - Non-owner rejection (403)
  - Prevent CID modification after creation
  - Authentication requirement

- ✅ **Delete Records** (DELETE /records/:id)
  - Delete record by patient
  - Database removal verification
  - Non-owner deletion rejection (403)
  - Grant revocation on deletion

- ✅ **Integration Tests**
  - Complete record lifecycle: create → retrieve → update → share → revoke → delete
  - Mocked Stellar and IPFS service calls

**Test Count**: ~22 test cases

---

### 4. [authorization.e2e-spec.ts](authorization.e2e-spec.ts) - Authorization & Role-Based Access Control
**Purpose**: End-to-end testing of role-based access control (RBAC), permission enforcement, and multi-role scenarios.

**Test Coverage**:
- ✅ **Admin-Only Endpoints**
  - GET /patients/admin/all - Admin can list all patients
  - Non-admin rejection (403)
  - Physics/Nurse/Patient rejection patterns
  - Unauthenticated rejection (401)

- ✅ **Admin Patient Search** (GET /patients)
  - Admin can search patients
  - Non-admin rejection

- ✅ **Admin Patient Admission** (POST /patients/:id/admit)
  - Admin can admit patients
  - Non-admin rejection

- ✅ **Provider-Protected Endpoints**
  - Physician access to provider endpoints
  - Nurse access to provider endpoints
  - Patient role verification

- ✅ **Patient Privacy & Data Isolation**
  - Prevent patient access to other patient records
  - Prevent patient access to other patient profiles
  - Data isolation enforcement

- ✅ **Role-Specific Authorization**
  - Physician authorization and profile access
  - Nurse authorization and profile access
  - Billing staff access restrictions
  - Clinical endpoint prevention for billing staff

- ✅ **Token-Based Authorization**
  - Valid JWT token acceptance
  - Invalid JWT token rejection
  - Missing Bearer token rejection
  - Missing Authorization header rejection

- ✅ **Permission Denial Scenarios**
  - 401 status for unauthenticated requests
  - 403 status for forbidden operations
  - Missing role requirement handling

- ✅ **Integration Tests**
  - Mixed-role operations
  - Privilege escalation prevention
  - Session invalidation after logout
  - Concurrent session management

**Test Count**: ~24 test cases

---

## Test Infrastructure Integration

### Database Setup
- **Test Database**: PostgreSQL (configured in `test/.env.test`)
- **Organization**: Database is started via Docker in `test/global-setup.ts`
- **Cleanup**: Each test clears relevant entities before running (beforeEach hooks)
- **Isolation**: Test database is separate from development/production databases

### Service Mocking
- **Stellar SDK**: Fully mocked in `test/setup-e2e.ts`
  - Server transactions
  - Keypair generation
  - TransactionBuilder operations
- **IPFS Client**: Fully mocked in `test/setup-e2e.ts`
  - File add/cat operations
  - Content retrieval
  - Pin operations

### JWT & Authentication
- **JWT Secret**: Test-specific secret from `test/.env.test`
- **Token Expiry**: Configured for tests (1h access, 7d refresh)
- **MFA**: Disabled for tests
- **Rate Limiting**: Disabled for tests

### HTTP Client
- **Framework**: Supertest for HTTP request simulation
- **Request Format**: Standard REST with JSON payloads
- **Response Validation**: Status codes and body structure assertions
- **Authorization**: Bearer token in Authorization header

## Running the E2E Tests

### All E2E Tests
```bash
npm run test:e2e
# or
jest --config jest.config.js --selectProjects=e2e
```

### Specific Test File
```bash
npm run test:e2e -- auth-and-patient.e2e-spec
npm run test:e2e -- access-control.e2e-spec
npm run test:e2e -- medical-records.e2e-spec
npm run test:e2e -- authorization.e2e-spec
```

### Watch Mode
```bash
npm run test:e2e -- --watch
```

### Coverage Report
```bash
npm run test:e2e -- --coverage
```

## Test Data and Fixtures

### Standard Test Users

**Patient User**:
```javascript
{
  firstName: 'John',
  lastName: 'Doe',
  email: 'john.doe@example.com',
  password: 'SecurePassword123!',
  dateOfBirth: '1990-01-15',
  gender: 'MALE',
  phoneNumber: '555-0123',
}
```

**Healthcare Provider (Physician)**:
```javascript
{
  firstName: 'Dr.',
  lastName: 'Smith',
  email: 'dr.smith@example.com',
  password: 'DoctorPassword123!',
  role: 'PHYSICIAN',
  npi: '1234567890',
  licenseNumber: 'MD123456',
}
```

### Standard Medical Record
```javascript
{
  cid: 'QmTestRecord123',
  recordType: 'consultation',
  description: 'Test record description',
  metadata: {
    provider: 'Dr. Smith',
    specialty: 'Cardiology',
    date: '2024-01-15'
  }
}
```

## Key Testing Patterns

### 1. User Registration → Login → Profile Flow
```javascript
// 1. Register
const registerResponse = await request(app.getHttpServer())
  .post('/auth/register')
  .send(userData)
  .expect(201);

// 2. Login
const loginResponse = await request(app.getHttpServer())
  .post('/auth/login')
  .send({ email: userData.email, password: userData.password })
  .expect(200);

// 3. Access profile with token
const meResponse = await request(app.getHttpServer())
  .get('/auth/me')
  .set('Authorization', `Bearer ${loginResponse.body.accessToken}`)
  .expect(200);
```

### 2. Access Grant → Verify → Revoke Pattern
```javascript
// 1. Grant access
const grantResponse = await request(app.getHttpServer())
  .post('/access/grant')
  .set('Authorization', `Bearer ${patientToken}`)
  .send({ granteeId, recordIds, accessLevel: 'READ' })
  .expect(201);

// 2. Verify access
const receivedResponse = await request(app.getHttpServer())
  .get('/access/received')
  .set('Authorization', `Bearer ${providerToken}`)
  .expect(200);

// 3. Revoke access
const revokeResponse = await request(app.getHttpServer())
  .delete(`/access/grant/${grantId}`)
  .set('Authorization', `Bearer ${patientToken}`)
  .expect(200);
```

### 3. Authorization Testing Pattern
```javascript
// Test successful operation
const successResponse = await request(app.getHttpServer())
  .get('/admin-endpoint')
  .set('Authorization', `Bearer ${adminToken}`)
  .expect(200);

// Test forbidden for non-admin
const forbiddenResponse = await request(app.getHttpServer())
  .get('/admin-endpoint')
  .set('Authorization', `Bearer ${patientToken}`)
  .expect(403);

// Test unauthenticated
const unauthorizedResponse = await request(app.getHttpServer())
  .get('/admin-endpoint')
  .expect(401);
```

## Test Scenarios Coverage Matrix

| Scenario | Auth Test | Access Test | Records Test | Auth Test |
|---|:---:|:---:|:---:|:---:|
| User Registration | ✅ | - | - | - |
| Patient/Provider Auth | ✅ | - | - | - |
| Access Grant Workflow | - | ✅ | - | - |
| Record CRUD | - | - | ✅ | - |
| Role-Based Access | - | - | - | ✅ |
| Admin Operations | ✅ | - | - | ✅ |
| Error Handling | ✅ | ✅ | ✅ | ✅ |
| Data Isolation | - | ✅ | ✅ | ✅ |
| Integration Flows | ✅ | ✅ | ✅ | ✅ |

## Acceptance Criteria Verification

✅ **Full HTTP Request/Response Cycle Testing**
- All tests use Supertest for real HTTP testing
- Request/response validation on every test

✅ **Test Database (PostgreSQL)**
- Tests use isolated PostgreSQL database
- Database setup/teardown in global-setup.ts
- Entity cleanup in beforeEach hooks

✅ **Mocked External Services**
- Stellar SDK fully mocked
- IPFS client fully mocked
- No external calls to blockchain or IPFS

✅ **CI/CD Compatible**
- Tests configured to run in jest.config.js
- Environment variables from test/.env.test
- Docker database orchestration for CI environments
- 60-second timeout for E2E tests

✅ **All Tests Passing**
- 84+ comprehensive test cases
- Full coverage of authentication flows
- Complete access control lifecycle testing
- Medical record CRUD validation
- Role-based authorization enforcement

## Troubleshooting

### Common Issues

**Issue**: Tests timeout
```
Increase Jest timeout in jest.config.js:
testTimeout: 120000
```

**Issue**: Database connection errors
```
Ensure PostgreSQL is running and accessible:
- Check TEST_DB_HOST, TEST_DB_PORT in test/.env.test
- Verify Docker container is running (if using Docker)
```

**Issue**: Token validation failures
```
Verify JWT_SECRET in test/.env.test matches auth configuration
```

**Issue**: IPFS/Stellar mock errors
```
Check that setup-e2e.ts is loaded before tests:
setupFilesAfterEnv: ['<rootDir>/test/setup-e2e.ts']
```

## Performance Notes

- **Test Suite Execution Time**: ~5-10 minutes for all 84+ tests
- **Database Operations**: Optimized with beforeEach cleanup
- **Service Mocking**: No external network calls
- **Cache Testing**: Includes 60-second access check cache validation

## Future Enhancements

Potential areas for expansion:
- GraphQL E2E tests (if GraphQL endpoint exists)
- WebSocket notification E2E tests
- Bulk import/export operation tests
- Emergency access scenarios
- Data residency compliance verification
- Performance/load E2E tests
- Concurrent access conflict resolution
- Audit log verification

## Documentation References

For more information, see:
- [API Key Authentication](../docs/api-key-authentication.md)
- [Logging Implementation](../docs/logging-implementation.md)
- [DISTRIBUTED TRACING](../docs/DISTRIBUTED_TRACING.md)
- [Authentication Guard Implementation](../src/auth/guards/)

---

**Last Updated**: January 2024
**Test Suite Version**: 1.0
**Status**: Production Ready ✅
