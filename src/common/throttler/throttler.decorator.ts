import { SetMetadata } from '@nestjs/common';

export const THROTTLER_LIMIT  = 'throttler:limit';
export const THROTTLER_TTL    = 'throttler:ttl';
export const THROTTLE_PROFILE = 'throttler:profile';

/**
 * Override the numeric limit and TTL for a specific handler.
 * @param limit - Max requests allowed in the window
 * @param ttlSeconds - Window size in seconds (default 60)
 */
export const RateLimit = (limit: number, ttlSeconds = 60) =>
  (target: any, propertyKey?: string, descriptor?: PropertyDescriptor) => {
    SetMetadata(THROTTLER_LIMIT, limit)(target, propertyKey, descriptor);
    SetMetadata(THROTTLER_TTL, ttlSeconds * 1000)(target, propertyKey, descriptor);
  };

/**
 * Pin a handler to a specific route-group key from RATE_LIMIT_PROFILES.
 * The actor type is still resolved at runtime from the request.
 *
 * @example \@ThrottleProfile('phi')   // uses phi:<actor> profile
 * @example \@ThrottleProfile('admin') // uses admin:<actor> profile
 */
export const ThrottleProfile = (group: string) => SetMetadata(THROTTLE_PROFILE, group);

// Convenience shorthands
export const AuthRateLimit      = () => RateLimit(10,  60);
export const VerifyRateLimit    = () => RateLimit(5,   60);
export const SensitiveRateLimit = () => RateLimit(20,  60);
export const PhiRateLimit       = () => ThrottleProfile('phi');
export const AdminRateLimit     = () => ThrottleProfile('admin');
