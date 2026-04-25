# Bugfix Requirements Document

## Introduction

Both `/webhooks/ipfs` and `/webhooks/stellar` endpoints are unauthenticated. They accept any HTTP POST body and unconditionally return `{ received: true }` without verifying the caller's identity. This allows an attacker to replay captured webhooks, forge arbitrary events, or flood the endpoints with oversized payloads to cause a request-body denial-of-service.

The fix introduces per-endpoint HMAC-SHA256 signature verification using separate secret keys, rejects requests with absent or invalid signatures with HTTP 401, preserves the raw request buffer for correct HMAC computation, and enforces a maximum body size limit.

## Bug Analysis

### Current Behavior (Defect)

1.1 WHEN a POST request is sent to `/webhooks/ipfs` without an `X-Signature` header THEN the system accepts the request and returns `{ received: true }`

1.2 WHEN a POST request is sent to `/webhooks/stellar` without an `X-Signature` header THEN the system accepts the request and returns `{ received: true }`

1.3 WHEN a POST request is sent to `/webhooks/ipfs` with a forged or invalid `X-Signature` header THEN the system accepts the request and returns `{ received: true }`

1.4 WHEN a POST request is sent to `/webhooks/stellar` with a forged or invalid `X-Signature` header THEN the system accepts the request and returns `{ received: true }`

1.5 WHEN a POST request with an arbitrarily large body is sent to `/webhooks/ipfs` or `/webhooks/stellar` THEN the system buffers the entire body without restriction, enabling a request-body denial-of-service

1.6 WHEN the middleware validates a signature THEN it uses a single shared `WEBHOOK_SECRET` environment variable rather than separate per-endpoint secrets (`IPFS_WEBHOOK_SECRET`, `STELLAR_WEBHOOK_SECRET`)

### Expected Behavior (Correct)

2.1 WHEN a POST request is sent to `/webhooks/ipfs` without an `X-Signature` header THEN the system SHALL reject the request with HTTP 401 Unauthorized

2.2 WHEN a POST request is sent to `/webhooks/stellar` without an `X-Signature` header THEN the system SHALL reject the request with HTTP 401 Unauthorized

2.3 WHEN a POST request is sent to `/webhooks/ipfs` with an invalid HMAC-SHA256 `X-Signature` (computed against `IPFS_WEBHOOK_SECRET`) THEN the system SHALL reject the request with HTTP 401 Unauthorized

2.4 WHEN a POST request is sent to `/webhooks/stellar` with an invalid HMAC-SHA256 `X-Signature` (computed against `STELLAR_WEBHOOK_SECRET`) THEN the system SHALL reject the request with HTTP 401 Unauthorized

2.5 WHEN a POST request body exceeds `MAX_WEBHOOK_BODY_SIZE` (1 MB) THEN the system SHALL reject the request with HTTP 413 Payload Too Large before signature verification

2.6 WHEN the HMAC is computed for `/webhooks/ipfs` THEN the system SHALL use the `IPFS_WEBHOOK_SECRET` environment variable as the signing key

2.7 WHEN the HMAC is computed for `/webhooks/stellar` THEN the system SHALL use the `STELLAR_WEBHOOK_SECRET` environment variable as the signing key

2.8 WHEN the HMAC is computed THEN the system SHALL compute it over the original raw request bytes (before JSON parsing) to prevent signature mismatch due to body re-serialization

### Unchanged Behavior (Regression Prevention)

3.1 WHEN a POST request is sent to `/webhooks/ipfs` with a valid HMAC-SHA256 `X-Signature` computed over the raw body using `IPFS_WEBHOOK_SECRET` THEN the system SHALL CONTINUE TO accept the request and return `{ received: true }`

3.2 WHEN a POST request is sent to `/webhooks/stellar` with a valid HMAC-SHA256 `X-Signature` computed over the raw body using `STELLAR_WEBHOOK_SECRET` THEN the system SHALL CONTINUE TO accept the request and return `{ received: true }`

3.3 WHEN a valid webhook request body is within the size limit THEN the system SHALL CONTINUE TO parse and process the JSON payload normally

3.4 WHEN other non-webhook endpoints receive requests THEN the system SHALL CONTINUE TO operate without being affected by the webhook-specific middleware or size restrictions
