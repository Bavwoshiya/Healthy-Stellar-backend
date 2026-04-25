import { Body, Controller, Get, HttpCode, HttpStatus, Post } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiBearerAuth, ApiBody } from '@nestjs/swagger';
import { SecretRotationService } from '../services/secret-rotation.service';

@ApiTags('Admin - Secret Rotation')
@ApiBearerAuth()
@Controller('admin/secret-rotation')
export class SecretRotationController {
  constructor(private readonly secretRotation: SecretRotationService) {}

  /**
   * Rotate the active JWT signing secret at runtime.
   * Tokens signed with the previous secret remain valid until they expire.
   */
  @Post('jwt/rotate')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Rotate JWT signing secret at runtime (zero-downtime)',
    description:
      'Promotes newSecret as the active signing key. The previous secret is ' +
      'kept in an overlap window so existing tokens remain verifiable until expiry.',
  })
  @ApiBody({
    schema: {
      type: 'object',
      required: ['newSecret', 'newVersion'],
      properties: {
        newSecret: { type: 'string', minLength: 32 },
        newVersion: { type: 'string', example: 'v2' },
      },
    },
  })
  rotateJwtSecret(
    @Body('newSecret') newSecret: string,
    @Body('newVersion') newVersion: string,
  ): { message: string; activeVersion: string } {
    this.secretRotation.rotateJwtSecret(newSecret, newVersion);
    return {
      message: 'JWT secret rotated successfully',
      activeVersion: this.secretRotation.activeVersion,
    };
  }

  @Get('status')
  @ApiOperation({ summary: 'List loaded secret versions and their activation timestamps' })
  status() {
    return this.secretRotation.status();
  }
}
