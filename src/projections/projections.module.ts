import { Module } from '@nestjs/common';
import { CqrsModule } from '@nestjs/cqrs';
import { TypeOrmModule } from '@nestjs/typeorm';
import { BullModule } from '@nestjs/bullmq';
import { ConfigModule, ConfigService } from '@nestjs/config';

import { EventEntity } from '../event-store/event.entity';
import { ProjectionCheckpoint } from './entities/projection-checkpoint.entity';
import { MedicalRecordReadModel } from './entities/medical-record-read.entity';
import { AccessGrantReadModel } from './entities/access-grant-read.entity';
import { AuditLogProjection } from './entities/audit-log-projection.entity';
import { AnalyticsSnapshot } from './entities/analytics-snapshot.entity';

import { RecordProjector } from './projectors/record.projector';
import { AccessGrantProjector } from './projectors/access-grant.projector';
import { AuditProjector } from './projectors/audit.projector';
import { AnalyticsProjector } from './projectors/analytics.projector';

import { ProjectionRebuildService, PROJECTION_REBUILD_QUEUE } from './services/projection-rebuild.service';
import { ProjectionRebuildProcessor } from './services/projection-rebuild.processor';
import { ProjectionsAdminController } from './controllers/projections-admin.controller';
import { createRedisRetryStrategy } from '../common/utils/connection-retry.util';

@Module({
  imports: [
    CqrsModule,
    TypeOrmModule.forFeature([
      EventEntity,
      ProjectionCheckpoint,
      MedicalRecordReadModel,
      AccessGrantReadModel,
      AuditLogProjection,
      AnalyticsSnapshot,
    ]),
    BullModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (cfg: ConfigService) => ({
        connection: {
          host: cfg.get('REDIS_HOST', 'localhost'),
          port: cfg.get<number>('REDIS_PORT', 6379),
          password: cfg.get('REDIS_PASSWORD'),
          maxRetriesPerRequest: null,
          retryStrategy: createRedisRetryStrategy(),
        },
      }),
      inject: [ConfigService],
    }),
    BullModule.registerQueue({ name: PROJECTION_REBUILD_QUEUE }),
  ],
  controllers: [ProjectionsAdminController],
  providers: [
    RecordProjector,
    AccessGrantProjector,
    AuditProjector,
    AnalyticsProjector,
    ProjectionRebuildService,
    ProjectionRebuildProcessor,
  ],
  exports: [CqrsModule],
})
export class ProjectionsModule {}
