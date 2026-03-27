import { EventsHandler, IEventHandler } from '@nestjs/cqrs';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { DomainEventPublished } from '../domain-event-published.event';
import { AuditLogProjection } from '../entities/audit-log-projection.entity';
import { ProjectionCheckpoint } from '../entities/projection-checkpoint.entity';

export const AUDIT_PROJECTOR = 'AuditProjector';

@EventsHandler(DomainEventPublished)
export class AuditProjector implements IEventHandler<DomainEventPublished> {
  constructor(
    @InjectRepository(AuditLogProjection)
    private readonly auditRepo: Repository<AuditLogProjection>,
    @InjectRepository(ProjectionCheckpoint)
    private readonly checkpointRepo: Repository<ProjectionCheckpoint>,
  ) {}

  async handle(event: DomainEventPublished): Promise<void> {
    const { domainEvent, globalVersion } = event;

    // Idempotent: skip if this version already logged
    const existing = await this.auditRepo.findOne({
      where: { aggregateId: domainEvent.aggregateId, version: domainEvent.version },
    });
    if (existing) return;

    await this.auditRepo.save(
      this.auditRepo.create({
        aggregateId: domainEvent.aggregateId,
        aggregateType: domainEvent.aggregateType,
        eventType: domainEvent.eventType,
        payload: domainEvent.payload,
        version: domainEvent.version,
      }),
    );

    await this.checkpointRepo.upsert(
      { projectorName: AUDIT_PROJECTOR, lastProcessedVersion: globalVersion },
      ['projectorName'],
    );
  }
}
