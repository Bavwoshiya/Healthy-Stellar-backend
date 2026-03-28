import { WebhookSignatureMiddleware } from './webhook-signature.middleware';
import { UnauthorizedException } from '@nestjs/common';
import * as crypto from 'crypto';

const IPFS_SECRET = 'ipfs-test-secret';
const STELLAR_SECRET = 'stellar-test-secret';
const SECRET_ENV = 'IPFS_WEBHOOK_SECRET';

/** Build a valid X-Signature header value */
function sign(body: string, secret: string, timestamp = Date.now()): string {
  const sig = crypto.createHmac('sha256', secret).update(`${timestamp}.${body}`).digest('hex');
  return `${timestamp}.${sig}`;
}

function makeReq(header: string | undefined, body = '{}'): any {
  return {
    headers: header !== undefined ? { 'x-signature': header } : {},
    rawBody: body,
  };
}

describe('WebhookSignatureMiddleware', () => {
  let middleware: WebhookSignatureMiddleware;

  beforeEach(() => {
    process.env[SECRET_ENV] = IPFS_SECRET;
    middleware = new WebhookSignatureMiddleware(SECRET_ENV);
  });

  afterEach(() => {
    delete process.env[SECRET_ENV];
    delete process.env['STELLAR_WEBHOOK_SECRET'];
  });

  // ── Construction ──────────────────────────────────────────────────────────

  it('throws on construction when env var is missing', () => {
    delete process.env[SECRET_ENV];
    expect(() => new WebhookSignatureMiddleware(SECRET_ENV)).toThrow(
      `${SECRET_ENV} environment variable is required`,
    );
  });

  it('constructs successfully when env var is present', () => {
    expect(() => new WebhookSignatureMiddleware(SECRET_ENV)).not.toThrow();
  });

  // ── Valid signature ───────────────────────────────────────────────────────

  it('calls next() for a valid signature', () => {
    const body = JSON.stringify({ event: 'pin.added' });
    const next = jest.fn();
    middleware.use(makeReq(sign(body, IPFS_SECRET), body), {} as any, next);
    expect(next).toHaveBeenCalledTimes(1);
  });

  it('uses rawBody bytes (not re-parsed JSON) for HMAC', () => {
    // Whitespace-sensitive: the raw body has extra spaces
    const rawBody = '{ "event" :  "pin.added" }';
    const next = jest.fn();
    middleware.use(makeReq(sign(rawBody, IPFS_SECRET), rawBody), {} as any, next);
    expect(next).toHaveBeenCalledTimes(1);
  });

  // ── Missing / malformed header ────────────────────────────────────────────

  it('throws 401 when X-Signature header is absent', () => {
    expect(() => middleware.use(makeReq(undefined), {} as any, jest.fn())).toThrow(
      UnauthorizedException,
    );
  });

  it('throws 401 when X-Signature has no dot separator', () => {
    expect(() => middleware.use(makeReq('invalidsignature'), {} as any, jest.fn())).toThrow(
      UnauthorizedException,
    );
  });

  it('throws 401 when timestamp part is empty', () => {
    expect(() => middleware.use(makeReq('.abc123'), {} as any, jest.fn())).toThrow(
      UnauthorizedException,
    );
  });

  it('throws 401 when signature part is empty', () => {
    const ts = Date.now();
    expect(() => middleware.use(makeReq(`${ts}.`), {} as any, jest.fn())).toThrow(
      UnauthorizedException,
    );
  });

  // ── Wrong secret ──────────────────────────────────────────────────────────

  it('throws 401 when signed with the wrong secret', () => {
    const body = JSON.stringify({ event: 'pin.added' });
    expect(() =>
      middleware.use(makeReq(sign(body, 'wrong-secret'), body), {} as any, jest.fn()),
    ).toThrow(UnauthorizedException);
  });

  // ── Replay attack prevention ──────────────────────────────────────────────

  it('throws 401 for a timestamp older than 5 minutes', () => {
    const body = '{}';
    const staleTs = Date.now() - 6 * 60 * 1000;
    const header = sign(body, IPFS_SECRET, staleTs);
    expect(() => middleware.use(makeReq(header, body), {} as any, jest.fn())).toThrow(
      UnauthorizedException,
    );
  });

  it('throws 401 for a non-numeric timestamp', () => {
    const body = '{}';
    const sig = crypto.createHmac('sha256', IPFS_SECRET).update(`NaN.${body}`).digest('hex');
    expect(() => middleware.use(makeReq(`NaN.${sig}`, body), {} as any, jest.fn())).toThrow(
      UnauthorizedException,
    );
  });

  // ── Per-endpoint secret isolation ─────────────────────────────────────────

  it('IPFS middleware rejects a payload signed with the Stellar secret', () => {
    const body = JSON.stringify({ tx: 'abc' });
    // Signed with Stellar secret but verified against IPFS secret
    expect(() =>
      middleware.use(makeReq(sign(body, STELLAR_SECRET), body), {} as any, jest.fn()),
    ).toThrow(UnauthorizedException);
  });

  it('Stellar middleware accepts a payload signed with the Stellar secret', () => {
    process.env['STELLAR_WEBHOOK_SECRET'] = STELLAR_SECRET;
    const stellarMiddleware = new WebhookSignatureMiddleware('STELLAR_WEBHOOK_SECRET');
    const body = JSON.stringify({ tx: 'abc' });
    const next = jest.fn();
    stellarMiddleware.use(makeReq(sign(body, STELLAR_SECRET), body), {} as any, next);
    expect(next).toHaveBeenCalledTimes(1);
  });

  it('Stellar middleware rejects a payload signed with the IPFS secret', () => {
    process.env['STELLAR_WEBHOOK_SECRET'] = STELLAR_SECRET;
    const stellarMiddleware = new WebhookSignatureMiddleware('STELLAR_WEBHOOK_SECRET');
    const body = JSON.stringify({ tx: 'abc' });
    expect(() =>
      stellarMiddleware.use(makeReq(sign(body, IPFS_SECRET), body), {} as any, jest.fn()),
    ).toThrow(UnauthorizedException);
  });
});
