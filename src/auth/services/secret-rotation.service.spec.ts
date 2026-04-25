import { Test, TestingModule } from '@nestjs/testing';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { SecretRotationService } from './secret-rotation.service';

const SECRET_V1 = 'a'.repeat(32);
const SECRET_V2 = 'b'.repeat(32);

function makeModule(secret = SECRET_V1, version = 'v1') {
  return Test.createTestingModule({
    providers: [
      SecretRotationService,
      {
        provide: ConfigService,
        useValue: {
          getOrThrow: jest.fn().mockReturnValue(secret),
          get: jest.fn((key: string, def?: string) => (key === 'JWT_SECRET_VERSION' ? version : def)),
        },
      },
      {
        provide: JwtService,
        useValue: new JwtService({}),
      },
    ],
  }).compile();
}

describe('SecretRotationService', () => {
  let service: SecretRotationService;
  let module: TestingModule;

  beforeEach(async () => {
    module = await makeModule();
    service = module.get(SecretRotationService);
    service.onModuleInit();
  });

  afterEach(() => module.close());

  it('initialises with the configured secret and version', () => {
    expect(service.activeVersion).toBe('v1');
    const status = service.status();
    expect(status).toHaveLength(1);
    expect(status[0]).toMatchObject({ version: 'v1', active: true });
  });

  it('signs a token verifiable with the active secret', () => {
    const token = service.sign({ userId: '123' });
    const payload = service.verify<{ userId: string }>(token);
    expect(payload?.userId).toBe('123');
  });

  it('rotates to a new secret and updates activeVersion', () => {
    service.rotateJwtSecret(SECRET_V2, 'v2');
    expect(service.activeVersion).toBe('v2');
    const status = service.status();
    expect(status).toHaveLength(2);
    expect(status[0]).toMatchObject({ version: 'v2', active: true });
    expect(status[1]).toMatchObject({ version: 'v1', active: false });
  });

  it('tokens signed before rotation remain verifiable during overlap window', () => {
    const oldToken = service.sign({ userId: 'old' });
    service.rotateJwtSecret(SECRET_V2, 'v2');
    // old token must still verify
    const payload = service.verify<{ userId: string }>(oldToken);
    expect(payload?.userId).toBe('old');
  });

  it('tokens signed after rotation verify with the new secret', () => {
    service.rotateJwtSecret(SECRET_V2, 'v2');
    const newToken = service.sign({ userId: 'new' });
    const payload = service.verify<{ userId: string }>(newToken);
    expect(payload?.userId).toBe('new');
  });

  it('returns null for a completely invalid token', () => {
    expect(service.verify('not.a.token')).toBeNull();
  });

  it('rejects a secret shorter than 32 characters', () => {
    expect(() => service.rotateJwtSecret('short', 'v2')).toThrow(
      'JWT secret must be at least 32 characters',
    );
  });

  it('rejects a duplicate version label', () => {
    expect(() => service.rotateJwtSecret(SECRET_V2, 'v1')).toThrow(
      'Secret version "v1" is already loaded',
    );
  });

  it('keeps only two slots after multiple rotations', () => {
    service.rotateJwtSecret(SECRET_V2, 'v2');
    service.rotateJwtSecret('c'.repeat(32), 'v3');
    expect(service.status()).toHaveLength(2);
    expect(service.activeVersion).toBe('v3');
  });
});
