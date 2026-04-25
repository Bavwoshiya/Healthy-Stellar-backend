import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, VersioningType, Controller, Get, Version, VERSION_NEUTRAL } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import * as request from 'supertest';
import { DeprecationInterceptor } from '../common/interceptors/deprecation.interceptor';
import { DeprecatedRoute } from '../common/decorators/deprecated.decorator';
import { ApiVersionLifecycleInterceptor } from './api-version-lifecycle.interceptor';
import { ApiVersionLifecyclePolicy } from './api-version-lifecycle.policy';

// ── Minimal test controllers ──────────────────────────────────────────────────

@Controller('test-v1')
class TestV1Controller {
  @Version('1')
  @Get()
  getV1() {
    return { version: 1 };
  }

  @Version('1')
  @Get('deprecated')
  @DeprecatedRoute({
    sunsetDate: 'Wed, 01 Jan 2030 00:00:00 GMT',
    alternativeRoute: '/v2/test-v1/deprecated',
  })
  getDeprecated() {
    return { version: 1, deprecated: true };
  }

  @Version('1')
  @Get('deprecated-gone')
  @DeprecatedRoute({
    sunsetDate: 'Wed, 01 Jan 2020 00:00:00 GMT',
    alternativeRoute: '/v2/test-v1/deprecated-gone',
    reason: 'This endpoint has been removed.',
  })
  getDeprecatedGone() {
    return { version: 1, deprecated: true };
  }
}

@Controller('test-v1')
class TestV2Controller {
  @Version('2')
  @Get()
  getV2() {
    return { version: 2 };
  }
}

@Controller('test-v1')
class TestV3Controller {
  @Version('3')
  @Get()
  getV3() {
    return { version: 3 };
  }
}

@Controller('test-neutral')
class TestNeutralController {
  @Version(VERSION_NEUTRAL)
  @Get()
  getNeutral() {
    return { neutral: true };
  }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('API Versioning (routing)', () => {
  let app: INestApplication;
  let httpApp: any;
  const now = () => new Date('2026-04-25T00:00:00.000Z');
  const policies: ApiVersionLifecyclePolicy[] = [
    {
      version: '1',
      status: 'current',
      releaseDate: '2024-01-01',
      baseUrl: '/v1',
    },
    {
      version: '2',
      status: 'deprecated',
      releaseDate: '2025-01-01',
      baseUrl: '/v2',
      sunsetDate: 'Wed, 01 Jan 2030 00:00:00 GMT',
      replacementVersion: '1',
    },
    {
      version: '3',
      status: 'sunset',
      releaseDate: '2023-01-01',
      baseUrl: '/v3',
      sunsetDate: 'Wed, 01 Jan 2025 00:00:00 GMT',
      replacementVersion: '1',
    },
  ];

  beforeAll(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [TestV1Controller, TestV2Controller, TestV3Controller, TestNeutralController],
    }).compile();

    app = module.createNestApplication();

    app.enableVersioning({ type: VersioningType.URI });
    app.useGlobalInterceptors(new ApiVersionLifecycleInterceptor(policies, now));
    app.useGlobalInterceptors(new DeprecationInterceptor(app.get(Reflector)));

    await app.init();
    httpApp = app.getHttpAdapter().getInstance();
  });

  afterAll(async () => {
    await app.close();
  });

  it('GET /v1/test-v1 routes to v1 controller', async () => {
    const res = await request(httpApp).get('/v1/test-v1').expect(200);
    expect(res.body.version).toBe(1);
  });

  it('GET /v2/test-v1 routes to v2 controller', async () => {
    const res = await request(httpApp).get('/v2/test-v1').expect(200);
    expect(res.body.version).toBe(2);
  });

  it('deprecated version returns deprecation headers', async () => {
    const res = await request(httpApp).get('/v2/test-v1').expect(200);
    expect(res.headers['deprecation']).toBe('true');
    expect(res.headers['sunset']).toBe('Wed, 01 Jan 2030 00:00:00 GMT');
    expect(res.headers['link']).toContain('/v1');
  });

  it('sunset version returns 410 Gone', async () => {
    const res = await request(httpApp).get('/v3/test-v1').expect(410);
    expect(String(res.body.message)).toContain('API version v3 is no longer available');
  });

  it('VERSION_NEUTRAL controller responds without version prefix', async () => {
    const res = await request(httpApp).get('/test-neutral').expect(200);
    expect(res.body.neutral).toBe(true);
  });

  it('deprecated endpoint returns Deprecation header', async () => {
    const res = await request(httpApp).get('/v1/test-v1/deprecated').expect(200);
    expect(res.headers['deprecation']).toBe('true');
  });

  it('deprecated endpoint returns Sunset header', async () => {
    const res = await request(httpApp).get('/v1/test-v1/deprecated').expect(200);
    expect(res.headers['sunset']).toBe('Wed, 01 Jan 2030 00:00:00 GMT');
  });

  it('deprecated endpoint returns Link header pointing to alternative', async () => {
    const res = await request(httpApp).get('/v1/test-v1/deprecated').expect(200);
    expect(res.headers['link']).toContain('/v2/test-v1/deprecated');
  });

  it('route-level sunset endpoint returns 410 Gone', async () => {
    const res = await request(httpApp).get('/v1/test-v1/deprecated-gone').expect(410);
    expect(String(res.body.message)).toContain('This endpoint is no longer available');
  });

  it('non-deprecated endpoint does NOT return Deprecation header', async () => {
    const res = await request(httpApp).get('/v1/test-v1').expect(200);
    expect(res.headers['deprecation']).toBeUndefined();
  });
});
