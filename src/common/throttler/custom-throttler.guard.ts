import { Injectable, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ThrottlerGuard, ThrottlerException } from '@nestjs/throttler';
import { THROTTLER_LIMIT, THROTTLER_TTL, THROTTLE_PROFILE } from './throttler.decorator';
import { resolveProfile, ActorType } from './throttler.config';
import { Request, Response } from 'express';

/** Map route prefixes to logical route groups used in RATE_LIMIT_PROFILES */
const ROUTE_GROUP_MAP: Array<[RegExp, string]> = [
  [/^\/auth/,        'auth'],
  [/^\/admin/,       'admin'],
  [/^\/reports/,     'reports'],
  [/^\/attachments/, 'upload'],
  [/^\/telemetry/,   'telemetry'],
  // PHI routes
  [/^\/medical-records/, 'phi'],
  [/^\/records/,         'phi'],
  [/^\/patients/,        'phi'],
  [/^\/pharmacy/,        'phi'],
  [/^\/laboratory/,      'phi'],
  [/^\/diagnosis/,       'phi'],
  [/^\/treatment/,       'phi'],
  [/^\/consents/,        'phi'],
];

function routeGroup(url: string): string {
  for (const [pattern, group] of ROUTE_GROUP_MAP) {
    if (pattern.test(url)) return group;
  }
  return '*';
}

function actorType(req: Request): ActorType {
  const user = (req as any).user;
  if (!user) return (req as any).apiKey ? 'api_key' : 'anonymous';
  const role: string = (user.role ?? user.roles?.[0] ?? '').toLowerCase();
  if (role.includes('admin'))    return 'admin';
  if (role.includes('provider') || role.includes('doctor') || role.includes('nurse')) return 'provider';
  if (role.includes('device'))   return 'device';
  if (role.includes('patient'))  return 'patient';
  return 'provider'; // authenticated but unknown role → conservative default
}

@Injectable()
export class CustomThrottlerGuard extends ThrottlerGuard {
  constructor(
    protected readonly options: any,
    protected readonly storageService: any,
    protected readonly reflector: Reflector,
  ) {
    super(options, storageService, reflector);
  }

  protected async getTracker(req: Request): Promise<string> {
    const user = (req as any).user;
    if (user) return user.stellarPublicKey || user.userId || user.id || this.ipFrom(req);
    const apiKey = (req as any).apiKey;
    if (apiKey?.id) return `api_key:${apiKey.id}`;
    return this.ipFrom(req);
  }

  private ipFrom(req: Request): string {
    const fwd = req.headers['x-forwarded-for'];
    if (fwd) return (Array.isArray(fwd) ? fwd[0] : fwd).split(',')[0].trim();
    const real = req.headers['x-real-ip'];
    if (real) return Array.isArray(real) ? real[0] : real;
    return req.ip || req.socket?.remoteAddress || 'unknown';
  }

  async handleRequest(context: ExecutionContext): Promise<boolean> {
    const request  = context.switchToHttp().getRequest<Request>();
    const response = context.switchToHttp().getResponse<Response>();
    const handler  = context.getHandler();
    const classRef = context.getClass();

    // 1. Explicit decorator overrides take highest priority
    const explicitLimit = this.reflector.getAllAndOverride<number>(THROTTLER_LIMIT, [handler, classRef]);
    const explicitTtl   = this.reflector.getAllAndOverride<number>(THROTTLER_TTL,   [handler, classRef]);
    const profileKey    = this.reflector.getAllAndOverride<string>(THROTTLE_PROFILE, [handler, classRef]);

    // 2. Resolve profile from route × actor matrix
    const actor  = actorType(request);
    const group  = profileKey ?? routeGroup(request.path ?? request.url);
    const profile = resolveProfile(group, actor);

    const limit = explicitLimit ?? profile.limit;
    const ttl   = explicitTtl   ?? profile.ttl;

    const tracker = await this.getTracker(request);
    const key = `throttle:${group}:${actor}:${tracker}`;

    const { totalHits, timeToExpire } = await this.storageService.increment(key, ttl);
    const remaining  = Math.max(0, limit - totalHits);
    const resetTime  = Math.ceil(Date.now() / 1000) + Math.ceil(timeToExpire / 1000);

    response.setHeader('X-RateLimit-Limit',     limit);
    response.setHeader('X-RateLimit-Remaining', remaining);
    response.setHeader('X-RateLimit-Reset',     resetTime);
    response.setHeader('X-RateLimit-Profile',   `${group}:${actor}`);

    if (totalHits > limit) {
      const retryAfter = Math.ceil(timeToExpire / 1000);
      response.setHeader('Retry-After', retryAfter);
      throw new ThrottlerException(`Rate limit exceeded. Retry after ${retryAfter}s.`);
    }

    return true;
  }
}
