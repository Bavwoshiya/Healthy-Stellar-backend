import { ThrottlerModuleOptions, ThrottlerOptionsFactory } from '@nestjs/throttler';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ThrottlerStorageRedisService } from 'nestjs-throttler-storage-redis';
import Redis from 'ioredis';

/** Actor types that influence rate limit selection */
export type ActorType = 'anonymous' | 'patient' | 'provider' | 'admin' | 'api_key' | 'device';

/** A single rate-limit profile */
export interface RateLimitProfile {
  /** Window in milliseconds */
  ttl: number;
  /** Max requests per window */
  limit: number;
}

/**
 * Route-pattern × actor-type rate limit matrix.
 *
 * Key format: `<routePattern>:<actorType>`
 * Fallback chain: exact match → `*:<actorType>` → `<routePattern>:*` → `*:*`
 */
export const RATE_LIMIT_PROFILES: Record<string, RateLimitProfile> = {
  // ── Authentication ──────────────────────────────────────────────────────────
  'auth:anonymous':  { ttl: 60_000, limit: 5   },  // brute-force protection
  'auth:patient':    { ttl: 60_000, limit: 10  },
  'auth:provider':   { ttl: 60_000, limit: 10  },
  'auth:admin':      { ttl: 60_000, limit: 10  },
  'auth:api_key':    { ttl: 60_000, limit: 20  },

  // ── PHI / Medical records ────────────────────────────────────────────────
  'phi:anonymous':   { ttl: 60_000, limit: 0   },  // blocked
  'phi:patient':     { ttl: 60_000, limit: 30  },
  'phi:provider':    { ttl: 60_000, limit: 60  },
  'phi:admin':       { ttl: 60_000, limit: 40  },
  'phi:api_key':     { ttl: 60_000, limit: 50  },
  'phi:device':      { ttl: 60_000, limit: 120 },

  // ── Admin operations ─────────────────────────────────────────────────────
  'admin:anonymous': { ttl: 60_000, limit: 0   },
  'admin:patient':   { ttl: 60_000, limit: 0   },
  'admin:provider':  { ttl: 60_000, limit: 5   },
  'admin:admin':     { ttl: 60_000, limit: 20  },
  'admin:api_key':   { ttl: 60_000, limit: 10  },

  // ── Reporting / analytics ────────────────────────────────────────────────
  'reports:anonymous': { ttl: 60_000, limit: 0  },
  'reports:patient':   { ttl: 60_000, limit: 10 },
  'reports:provider':  { ttl: 60_000, limit: 30 },
  'reports:admin':     { ttl: 60_000, limit: 60 },
  'reports:api_key':   { ttl: 60_000, limit: 40 },

  // ── Device telemetry ─────────────────────────────────────────────────────
  'telemetry:device':  { ttl: 60_000, limit: 300 },
  'telemetry:*':       { ttl: 60_000, limit: 60  },

  // ── File uploads ─────────────────────────────────────────────────────────
  'upload:anonymous':  { ttl: 60_000, limit: 0  },
  'upload:patient':    { ttl: 60_000, limit: 5  },
  'upload:provider':   { ttl: 60_000, limit: 20 },
  'upload:admin':      { ttl: 60_000, limit: 20 },
  'upload:api_key':    { ttl: 60_000, limit: 10 },

  // ── Global fallback ───────────────────────────────────────────────────────
  '*:anonymous':       { ttl: 60_000, limit: 30  },
  '*:patient':         { ttl: 60_000, limit: 100 },
  '*:provider':        { ttl: 60_000, limit: 200 },
  '*:admin':           { ttl: 60_000, limit: 150 },
  '*:api_key':         { ttl: 60_000, limit: 100 },
  '*:device':          { ttl: 60_000, limit: 300 },
  '*:*':               { ttl: 60_000, limit: 30  },
};

/**
 * Resolve the best-matching profile for a given route group and actor.
 * Fallback chain: `route:actor` → `*:actor` → `route:*` → `*:*`
 */
export function resolveProfile(routeGroup: string, actor: ActorType): RateLimitProfile {
  return (
    RATE_LIMIT_PROFILES[`${routeGroup}:${actor}`] ??
    RATE_LIMIT_PROFILES[`*:${actor}`] ??
    RATE_LIMIT_PROFILES[`${routeGroup}:*`] ??
    RATE_LIMIT_PROFILES['*:*']
  );
}

@Injectable()
export class ThrottlerConfigService implements ThrottlerOptionsFactory {
  constructor(private configService: ConfigService) {}

  createThrottlerOptions(): ThrottlerModuleOptions {
    const redisHost = this.configService.get<string>('REDIS_HOST', 'localhost');
    const redisPort = this.configService.get<number>('REDIS_PORT', 6379);
    const redisPassword = this.configService.get<string>('REDIS_PASSWORD');
    const redisDb = this.configService.get<number>('REDIS_DB', 0);

    const redis = new Redis({
      host: redisHost,
      port: redisPort,
      password: redisPassword || undefined,
      db: redisDb,
      retryStrategy: (times) => Math.min(times * 50, 2000),
    });

    // A single named throttler is registered; the guard overrides ttl/limit
    // per-request using RATE_LIMIT_PROFILES, so this acts as a safe fallback.
    return {
      throttlers: [{ name: 'default', ttl: 60_000, limit: 30 }],
      storage: new ThrottlerStorageRedisService(redis),
    };
  }
}
