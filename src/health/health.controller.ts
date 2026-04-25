import { Controller, Get, UseGuards, Version, VERSION_NEUTRAL } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { HealthCheck, HealthCheckService, TypeOrmHealthIndicator } from '@nestjs/terminus';
import { AdminGuard } from '../auth/guards/admin.guard';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { CircuitBreakerService } from '../common/circuit-breaker/circuit-breaker.service';
import { Public } from '../common/decorators/public.decorator';
import { RegionalDatabaseService } from '../data-residency/services/regional-database.service';
import { RegionalIpfsService } from '../data-residency/services/regional-ipfs.service';
import { DataResidencyRegion } from '../enums/data-residency.enum';
import { DetailedHealthIndicator } from './indicators/detailed-health.indicator';
import { IpfsHealthIndicator } from './indicators/ipfs.health';
import { RedisHealthIndicator } from './indicators/redis.health';
import { StellarHealthIndicator } from './indicators/stellar.health';

@ApiTags('health')
@Version(VERSION_NEUTRAL)
@Controller('health')
@Public()
export class HealthController {
  constructor(
    private health: HealthCheckService,
    private db: TypeOrmHealthIndicator,
    private redis: RedisHealthIndicator,
    private ipfs: IpfsHealthIndicator,
    private stellar: StellarHealthIndicator,
    private detailedHealth: DetailedHealthIndicator,
    private syntheticProbe: SyntheticProbeIndicator,
    private circuitBreaker: CircuitBreakerService,
    private regionalDatabase: RegionalDatabaseService,
    private regionalIpfs: RegionalIpfsService,
  ) {}

  @Get()
  @HealthCheck()
  @ApiOperation({ summary: 'Overall system health (liveness probe)' })
  @ApiResponse({ status: 200, description: 'System is alive' })
  check() {
    return this.health.check([() => this.db.pingCheck('database', { timeout: 3000 })]);
  }

  @Get('ready')
  @HealthCheck()
  @ApiOperation({ summary: 'Readiness probe (all dependencies healthy)' })
  @ApiResponse({ status: 200, description: 'System is ready' })
  @ApiResponse({ status: 503, description: 'System is not ready' })
  async checkReadiness() {
    const healthChecks = await this.health.check([
      () => this.db.pingCheck('database', { timeout: 3000 }),
      () => this.redis.isHealthy('redis'),
      () => this.ipfs.isHealthy('ipfs'),
      () => this.stellar.isHealthy('stellar'),
    ]);

    return {
      ...healthChecks,
      circuitBreakers: this.circuitBreaker.getAllStates(),
    };
  }

  @Get('detailed')
  @UseGuards(JwtAuthGuard, AdminGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Detailed admin health diagnostics' })
  @ApiResponse({ status: 200, description: 'Detailed health report' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 403, description: 'Forbidden – admin only' })
  getDetailedHealth() {
    return this.detailedHealth.getDetailedHealth();
  }

  @Get('circuit-breakers')
  @ApiOperation({ summary: 'Get circuit breaker states' })
  @ApiResponse({ status: 200, description: 'Circuit breaker states retrieved' })
  getCircuitBreakerStates() {
    return {
      states: this.circuitBreaker.getAllStates(),
      details: this.circuitBreaker.getDetailedStats(),
    };
  }

  @Get('data-residency')
  @ApiOperation({ summary: 'Regional database and IPFS node connectivity' })
  @ApiResponse({ status: 200, description: 'Per-region health status' })
  async checkDataResidency() {
    const regions = Object.values(DataResidencyRegion);

    const [dbHealth, ipfsHealth] = await Promise.all([
      this.regionalDatabase.getRegionalHealthStatus(),
      Promise.all(
        regions.map(async (region) => ({
          region,
          nodes: await this.regionalIpfs.checkRegionalNodesHealth(region),
        })),
      ),
    ]);

    const ipfsResult = Object.fromEntries(ipfsHealth.map(({ region, nodes }) => [region, nodes]));

    return {
      database: dbHealth,
      ipfs: ipfsResult,
      timestamp: new Date().toISOString(),
    };
  }

  @Get('synthetic')
  @HealthCheck()
  @ApiOperation({ summary: 'Synthetic probes for critical user journeys' })
  @ApiResponse({ status: 200, description: 'Business-level availability validated' })
  @ApiResponse({ status: 503, description: 'Critical user journey unavailable' })
  async checkSyntheticProbes() {
    return this.health.check([() => this.syntheticProbe.isHealthy('synthetic-probe')]);
  }
}
