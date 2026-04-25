import { Controller, Get, Post, Query, UseGuards } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { QueryPerformanceMonitor } from '../services/query-performance-monitor.service';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { Roles } from '../../auth/decorators/roles.decorator';
import { RolesGuard } from '../../auth/guards/roles.guard';

@ApiTags('Query Performance')
@Controller('admin/query-performance')
@UseGuards(JwtAuthGuard, RolesGuard)
@ApiBearerAuth()
export class QueryPerformanceController {
  constructor(private readonly monitor: QueryPerformanceMonitor) {}

  @Get('slow-queries')
  @Roles('admin', 'system_admin')
  @ApiOperation({ summary: 'Get slow queries from pg_stat_statements' })
  @ApiResponse({ status: 200, description: 'List of slow queries' })
  async getSlowQueries(@Query('limit') limit?: number) {
    return this.monitor.getSlowQueries(limit || 10);
  }

  @Post('reset-stats')
  @Roles('admin', 'system_admin')
  @ApiOperation({ summary: 'Reset query statistics' })
  @ApiResponse({ status: 200, description: 'Statistics reset successfully' })
  async resetStats() {
    await this.monitor.resetStats();
    return { message: 'Query statistics reset successfully' };
  }
}
