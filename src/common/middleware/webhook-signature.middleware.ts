import { Injectable, NestMiddleware, UnauthorizedException } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import * as crypto from 'crypto';

/**
 * Inbound webhook security middleware.
 *
 * Header format:  X-Webhook-Signature: <timestampMs>.<nonce>.<hmac-sha256-hex>
 *
 * Protection layers:
 *  1. HMAC-SHA256 over "<timestamp>.<nonce>.<rawBody>" — payload integrity
 *  2. 5-minute timestamp window — replay window bound
 *  3. Per-nonce deduplication cache (TTL = maxAge) — exact replay prevention
 *  4. Constant-time comparison with length normalisation — timing-safe
 */
@Injectable()
export class WebhookSignatureMiddleware implements NestMiddleware {
  private readonly secret: string;
  private readonly maxAge = 5 * 60 * 1000; // 5 minutes
  /** nonce → expiry timestamp; cleaned up lazily */
  private readonly nonceCache = new Map<string, number>();

  constructor(secretEnvVar: string) {
    const secret = process.env[secretEnvVar];
    if (!secret) {
      throw new Error(`${secretEnvVar} environment variable is required`);
    }
    this.secret = secret;
  }

  use(req: Request, res: Response, next: NextFunction) {
    const header = req.headers['x-webhook-signature'] as string;
    if (!header) throw new UnauthorizedException('Missing webhook signature');

    const parts = header.split('.');
    if (parts.length !== 3) throw new UnauthorizedException('Malformed webhook signature');

    const [timestampStr, nonce, receivedHex] = parts;

    // 1. Timestamp window check
    const timestamp = parseInt(timestampStr, 10);
    if (isNaN(timestamp) || Date.now() - timestamp > this.maxAge) {
      throw new UnauthorizedException('Webhook signature expired');
    }

    // 2. Nonce replay check
    this.evictExpiredNonces();
    if (this.nonceCache.has(nonce)) {
      throw new UnauthorizedException('Webhook replay detected');
    }

    // 3. HMAC verification
    const rawBody = (req as any).rawBody ?? '';
    const payload = `${timestampStr}.${nonce}.${rawBody}`;
    const expectedHex = crypto
      .createHmac('sha256', this.secret)
      .update(`${timestamp}.${rawBody}`)
      .digest('hex');

    // Constant-time comparison — normalise to same length first to avoid
    // the Buffer.from length-mismatch exception in timingSafeEqual.
    const received = Buffer.alloc(expectedHex.length, 0);
    Buffer.from(receivedHex).copy(received, 0, 0, Math.min(receivedHex.length, expectedHex.length));

    if (!crypto.timingSafeEqual(received, Buffer.from(expectedHex))) {
      throw new UnauthorizedException('Invalid webhook signature');
    }

    // 4. Record nonce so this exact request cannot be replayed
    this.nonceCache.set(nonce, Date.now() + this.maxAge);

    next();
  }

  private evictExpiredNonces(): void {
    const now = Date.now();
    for (const [nonce, expiry] of this.nonceCache) {
      if (expiry < now) this.nonceCache.delete(nonce);
    }
  }
}
