import {
  CallHandler,
  ExecutionContext,
  GoneException,
  Injectable,
  NestInterceptor,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import {
  API_VERSION_LIFECYCLE_POLICIES,
  ApiVersionLifecyclePolicy,
} from './api-version-lifecycle.policy';

@Injectable()
export class ApiVersionLifecycleInterceptor implements NestInterceptor {
  constructor(
    private readonly policies: ApiVersionLifecyclePolicy[] = API_VERSION_LIFECYCLE_POLICIES,
    private readonly nowProvider: () => Date = () => new Date(),
  ) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const http = context.switchToHttp();
    const request = http.getRequest();
    const response = http.getResponse();

    const version = this.extractUriVersion(request?.originalUrl ?? request?.url ?? '');
    if (!version) return next.handle();

    const policy = this.policies.find((p) => p.version === version);
    if (!policy) return next.handle();

    if (policy.status === 'deprecated') {
      response.setHeader('Deprecation', 'true');
      if (policy.sunsetDate) response.setHeader('Sunset', policy.sunsetDate);
      if (policy.replacementVersion) {
        response.setHeader('Link', `</v${policy.replacementVersion}>; rel="alternate"`);
      }
    }

    if (this.isSunset(policy)) {
      throw new GoneException(this.buildSunsetMessage(policy));
    }

    return next.handle();
  }

  private isSunset(policy: ApiVersionLifecyclePolicy): boolean {
    if (policy.status === 'sunset') return true;
    if (policy.status !== 'deprecated' || !policy.sunsetDate) return false;

    const sunsetTime = Date.parse(policy.sunsetDate);
    if (Number.isNaN(sunsetTime)) return false;

    return this.nowProvider().getTime() >= sunsetTime;
  }

  private buildSunsetMessage(policy: ApiVersionLifecyclePolicy): string {
    const replacement = policy.replacementVersion ? ` Use /v${policy.replacementVersion} instead.` : '';
    const sunset = policy.sunsetDate ? ` Sunset date: ${policy.sunsetDate}.` : '';
    return `API version v${policy.version} is no longer available.${sunset}${replacement}`.trim();
  }

  private extractUriVersion(urlPath: string): string | null {
    const match = /^\/v(\d+)(?:\/|$)/i.exec(urlPath);
    return match?.[1] ?? null;
  }
}
