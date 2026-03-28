import { Injectable, NestMiddleware, UnauthorizedException } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import * as crypto from 'crypto';

/**
 * HMAC-SHA256 signature verification middleware for webhook endpoints.
 *
 * Expects header: X-Signature: {timestamp}.{hmac-sha256-hex}
 * where the HMAC is computed over `{timestamp}.{rawBody}`.
 *
 * Instantiate with the appropriate secret env-var name per route:
 *   new WebhookSignatureMiddleware('IPFS_WEBHOOK_SECRET')
 *   new WebhookSignatureMiddleware('STELLAR_WEBHOOK_SECRET')
 */
@Injectable()
export class WebhookSignatureMiddleware implements NestMiddleware {
  private readonly secret: string;
  private readonly maxAge = 5 * 60 * 1000; // 5-minute replay window

  constructor(secretEnvVar: string) {
    const secret = process.env[secretEnvVar];
    if (!secret) {
      throw new Error(`${secretEnvVar} environment variable is required`);
    }
    this.secret = secret;
  }

  use(req: Request, _res: Response, next: NextFunction): void {
    const header = req.headers['x-signature'] as string | undefined;

    if (!header) {
      throw new UnauthorizedException();
    }

    const dotIndex = header.indexOf('.');
    if (dotIndex === -1) {
      throw new UnauthorizedException();
    }

    const timestamp = header.slice(0, dotIndex);
    const receivedSig = header.slice(dotIndex + 1);

    if (!timestamp || !receivedSig) {
      throw new UnauthorizedException();
    }

    const requestTime = parseInt(timestamp, 10);
    if (isNaN(requestTime) || Date.now() - requestTime > this.maxAge) {
      throw new UnauthorizedException();
    }

    const rawBody = (req as any).rawBody ?? '';
    const expected = crypto
      .createHmac('sha256', this.secret)
      .update(`${timestamp}.${rawBody}`)
      .digest('hex');

    // Constant-time comparison to prevent timing attacks
    try {
      if (!crypto.timingSafeEqual(Buffer.from(receivedSig, 'hex'), Buffer.from(expected, 'hex'))) {
        throw new UnauthorizedException();
      }
    } catch {
      // timingSafeEqual throws if buffers differ in length
      throw new UnauthorizedException();
    }

    next();
  }
}
