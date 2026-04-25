import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';

interface SecretSlot {
  version: string;
  secret: string;
  activatedAt: Date;
}

/**
 * Manages runtime rotation of JWT signing secrets without a process restart.
 *
 * Rotation model:
 *   1. Caller supplies a new secret + version via rotateJwtSecret().
 *   2. The new secret becomes active immediately for all new token issuance.
 *   3. The previous secret is kept in the overlap window so tokens signed
 *      with it remain valid until they naturally expire (≤ JWT_EXPIRATION).
 *   4. Only the two most-recent versions are kept in memory at any time.
 */
@Injectable()
export class SecretRotationService implements OnModuleInit {
  private readonly logger = new Logger(SecretRotationService.name);

  /** Ordered newest-first; max 2 entries (active + previous). */
  private slots: SecretSlot[] = [];

  constructor(
    private readonly config: ConfigService,
    private readonly jwtService: JwtService,
  ) {}

  onModuleInit(): void {
    const secret = this.config.getOrThrow<string>('JWT_SECRET');
    const version = this.config.get<string>('JWT_SECRET_VERSION', 'v1');
    this.slots = [{ version, secret, activatedAt: new Date() }];
    this.logger.log(`SecretRotationService initialised — active JWT secret version: ${version}`);
  }

  // ── Public API ─────────────────────────────────────────────────────────────

  /** Active secret used for signing new tokens. */
  get activeSecret(): string {
    return this.slots[0].secret;
  }

  /** Active version label. */
  get activeVersion(): string {
    return this.slots[0].version;
  }

  /**
   * Rotate to a new JWT secret at runtime.
   * The previous secret is retained for the overlap window so in-flight tokens
   * remain verifiable until they expire.
   *
   * @param newSecret  New HMAC secret (min 32 chars recommended).
   * @param newVersion Caller-supplied version label (e.g. "v2", "2024-07-01").
   */
  rotateJwtSecret(newSecret: string, newVersion: string): void {
    if (!newSecret || newSecret.length < 32) {
      throw new Error('JWT secret must be at least 32 characters');
    }
    if (this.slots.some((s) => s.version === newVersion)) {
      throw new Error(`Secret version "${newVersion}" is already loaded`);
    }

    // Keep only the current active slot as the "previous" overlap slot.
    this.slots = [
      { version: newVersion, secret: newSecret, activatedAt: new Date() },
      this.slots[0],
    ];

    this.logger.log(
      `JWT secret rotated — new active version: ${newVersion}, ` +
        `previous version ${this.slots[1].version} retained for overlap window`,
    );
  }

  /**
   * Sign a payload with the currently active secret.
   * Passes through all options to JwtService.sign().
   */
  sign(payload: object, options?: Parameters<JwtService['sign']>[1]): string {
    return this.jwtService.sign(payload, {
      ...options,
      secret: this.activeSecret,
    });
  }

  /**
   * Verify a token against all live secret versions.
   * Returns the decoded payload on success, null if no version validates it.
   */
  verify<T extends object = Record<string, unknown>>(
    token: string,
    options?: Parameters<JwtService['verify']>[1],
  ): T | null {
    for (const slot of this.slots) {
      try {
        return this.jwtService.verify<T>(token, { ...options, secret: slot.secret });
      } catch {
        // try next slot
      }
    }
    return null;
  }

  /** Returns metadata about currently loaded secret versions (no secret values). */
  status(): Array<{ version: string; activatedAt: Date; active: boolean }> {
    return this.slots.map((s, i) => ({
      version: s.version,
      activatedAt: s.activatedAt,
      active: i === 0,
    }));
  }
}
