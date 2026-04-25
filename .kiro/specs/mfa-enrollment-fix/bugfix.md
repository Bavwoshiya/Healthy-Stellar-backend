# Bugfix Requirements Document

## Introduction

`MfaService.setupMfa` generates a TOTP secret and returns it to the client but never persists it. When the user subsequently calls `verifyAndEnableMfa`, the method calls `speakeasy.generateSecret` again, producing a completely different secret, and then verifies the user's TOTP code against that new, unrelated secret. Verification always fails, making the entire MFA enrollment flow non-functional. Additionally, backup codes generated during setup are discarded and never saved, so account recovery is impossible. A missing TOTP window tolerance also risks time-drift failures for users with slightly off-sync device clocks.

## Bug Analysis

### Current Behavior (Defect)

1.1 WHEN a user calls `POST /auth/mfa/setup`, THEN the system generates a TOTP secret and returns it to the client but does not persist it anywhere.

1.2 WHEN a user calls `POST /auth/mfa/verify` with a valid 6-digit TOTP code, THEN the system generates a brand-new, unrelated secret and verifies the code against it, causing verification to always fail.

1.3 WHEN a user calls `POST /auth/mfa/setup`, THEN the system generates backup codes and returns them to the client but does not save them to the database, making them unusable for account recovery.

1.4 WHEN a user's device clock is slightly off-sync, THEN the system rejects a valid TOTP code because no time-drift window tolerance is configured in `setupMfa`.

### Expected Behavior (Correct)

2.1 WHEN a user calls `POST /auth/mfa/setup`, THEN the system SHALL persist the generated TOTP secret in a temporary pending state (e.g., stored on the `mfa_entities` record with a pending/unverified flag, or in a short-lived cache scoped to the user) so it can be retrieved during verification.

2.2 WHEN a user calls `POST /auth/mfa/verify` with a valid 6-digit TOTP code, THEN the system SHALL load the previously persisted pending secret for that user, verify the code against it, and only then commit the MFA record as active and verified.

2.3 WHEN a user calls `POST /auth/mfa/setup`, THEN the system SHALL persist the generated backup codes alongside the pending secret so they are available for account recovery after enrollment is confirmed.

2.4 WHEN a user's device clock is slightly off-sync (within a reasonable drift window), THEN the system SHALL accept a valid TOTP code by applying a configurable time-step window tolerance during verification.

### Unchanged Behavior (Regression Prevention)

3.1 WHEN a user has already completed MFA enrollment and calls `POST /auth/mfa/verify-login` with a correct TOTP code, THEN the system SHALL CONTINUE TO validate the code against the stored active secret and grant access.

3.2 WHEN a user has already completed MFA enrollment and uses a valid backup code, THEN the system SHALL CONTINUE TO accept it, consume it, and remove it from the stored list.

3.3 WHEN a user calls `POST /auth/mfa/disable` with a valid TOTP code, THEN the system SHALL CONTINUE TO deactivate all MFA devices and clear the MFA flag on the user record.

3.4 WHEN a user calls `POST /auth/mfa/setup` but never completes verification, THEN the system SHALL CONTINUE TO leave the user's MFA status as disabled.

---

## Bug Condition Pseudocode

### Bug Condition Function

```pascal
FUNCTION isBugCondition(X)
  INPUT: X of type MfaEnrollmentAttempt { userId, totpCode, setupSecret }
  OUTPUT: boolean

  // Bug is triggered when the user attempts to verify a code from a setup
  // session where the secret was never persisted
  RETURN X.setupSecret IS NOT NULL
     AND persistedPendingSecret(X.userId) IS NULL
END FUNCTION
```

### Fix Checking Property

```pascal
// Property: Fix Checking — Verification uses the same secret as setup
FOR ALL X WHERE isBugCondition(X) DO
  result ← verifyAndEnableMfa'(X.userId, X.totpCode)
  ASSERT result.success = true
     AND persistedActiveSecret(X.userId) = X.setupSecret
END FOR
```

### Preservation Checking Property

```pascal
// Property: Preservation Checking — Already-enrolled users are unaffected
FOR ALL X WHERE NOT isBugCondition(X) DO
  ASSERT verifyMfaCode'(X.userId, X.totpCode) = verifyMfaCode(X.userId, X.totpCode)
END FOR
```
