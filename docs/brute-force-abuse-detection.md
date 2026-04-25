# Brute-Force and Abuse Detection Pipeline

> Implementation plan for issue [#435](https://github.com/Healthy-Stellar/Healthy-Stellar-backend/issues/435)

## Overview

Protect authentication and sensitive endpoints from brute-force attacks, credential stuffing, and API abuse using a layered detection pipeline backed by Redis.

---

## Architecture

```
Request → IP Extraction Middleware
        → Rate Limit Guard (per-IP, per-user)
        → Attempt Tracker (Redis sliding window)
        → Lockout Enforcer
        → Suspicious Pattern Detector
        → Audit Logger
        → Response
```

---

## Components

### 1. Redis-Backed Attempt Tracker
- Key pattern: `brute:<type>:<identifier>` (e.g. `brute:login:192.168.1.1`)
- Sliding window counter using Redis `INCR` + `EXPIRE`
- Separate counters for: login attempts, password reset, OTP, sensitive endpoints
- TTL resets on each attempt within the window

### 2. Rate Limit Guard (`BruteForceGuard`)
- NestJS `CanActivate` guard applied to auth endpoints
- Thresholds (configurable via env):
  - `MAX_LOGIN_ATTEMPTS=5` per 15 minutes per IP
  - `MAX_LOGIN_ATTEMPTS_PER_USER=10` per 15 minutes per username
  - `MAX_RESET_ATTEMPTS=3` per hour per IP
- Returns `429 Too Many Requests` with `Retry-After` header on breach

### 3. Progressive Lockout
- 5 failures → 15-minute lockout
- 10 failures → 1-hour lockout
- 20 failures → 24-hour lockout
- Lockout state stored in Redis: `lockout:<identifier>`

### 4. Suspicious Pattern Detection
- Flag requests matching:
  - Same IP hitting multiple usernames (credential stuffing)
  - Distributed IPs hitting same username (distributed brute-force)
  - Abnormal request velocity (>20 req/min from single IP)
- Use Redis sorted sets for pattern analysis

### 5. IP Extraction & Proxy Awareness
- Respect `X-Forwarded-For` and `X-Real-IP` headers
- Configurable trusted proxy list to prevent IP spoofing
- Fall back to `req.ip` when no trusted proxy header present

### 6. Audit Logging
- Log all lockout events and suspicious patterns to existing `AuditService`
- Fields: `ip`, `userId`, `endpoint`, `attemptCount`, `action` (locked/flagged/allowed), `timestamp`

### 7. Notification Hook
- Emit event to existing `NotificationsService` when lockout or suspicious pattern is triggered
- Admins receive alert for distributed attack patterns

---

## Module Structure

```
src/brute-force/
├── brute-force.module.ts
├── brute-force.service.ts        # Core attempt tracking & lockout logic
├── brute-force.guard.ts          # NestJS guard
├── brute-force.middleware.ts     # IP extraction
├── dto/
│   └── attempt-record.dto.ts
└── constants/
    └── thresholds.ts
```

---

## Integration Points

- Apply `BruteForceGuard` to: `POST /auth/login`, `POST /auth/refresh`, `POST /auth/reset-password`, `POST /auth/verify-otp`
- Apply lighter rate limiting to all other sensitive endpoints via global throttler
- Plug into existing `AuditService` for logging
- Plug into existing `NotificationsService` for alerts
- Use existing `ioredis` instance (already in project)

---

## Environment Variables

```env
BRUTE_FORCE_MAX_LOGIN_ATTEMPTS=5
BRUTE_FORCE_LOGIN_WINDOW_SECONDS=900
BRUTE_FORCE_MAX_RESET_ATTEMPTS=3
BRUTE_FORCE_RESET_WINDOW_SECONDS=3600
BRUTE_FORCE_LOCKOUT_DURATIONS=900,3600,86400
BRUTE_FORCE_TRUSTED_PROXIES=127.0.0.1,10.0.0.0/8
```

---

## Acceptance Criteria

- [ ] Login endpoint returns `429` after threshold exceeded
- [ ] Lockout persists across server restarts (Redis-backed)
- [ ] Credential stuffing pattern triggers admin alert
- [ ] All lockout events appear in audit log
- [ ] Lockout duration escalates progressively
- [ ] IP spoofing via forged headers is mitigated
- [ ] Guard is unit-testable with mocked Redis
