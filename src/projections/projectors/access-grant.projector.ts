import { EventsHandler, IEventHandler } from '@nestjs/cqrs';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { DomainEventPublished } from '../domain-event-published.event';
import { AccessGrantReadModel } from '../entities/access-grant-read.entity';
import { ProjectionCheckpoint } from '../entities/projection-checkpoint.entity';

export const ACCESS_GRANT_PROJECTOR = 'AccessGrantProjector';

@EventsHandler(DomainEventPublished)
export class AccessGrantProjector implements IEventHandler<DomainEventPublished> {
  constructor(
    @InjectRepository(AccessGrantReadModel)
    private readonly readRepo: Repository<AccessGrantReadModel>,
    @InjectRepository(ProjectionCheckpoint)
    private readonly checkpointRepo: Repository<ProjectionCheckpoint>,
  ) {}

  async handle(event: DomainEventPublished): Promise<void> {
    const { domainEvent, globalVersion } = event;
    const { eventType, aggregateId, payload, version } = domainEvent;

    switch (eventType) {
      case 'AccessGranted': {
        const p = payload as any;
        await this.readRepo.upsert(
          {
            aggregateId,
            patientId: p.patientId ?? aggregateId,
            grantedTo: p.grantedTo,
            grantedBy: p.grantedBy,
            status: 'ACTIVE',
            expiresAt: p.expiresAt ? new Date(p.expiresAt) : null,
            version,
          },
          ['aggregateId'],
        );
        break;
      }
      case 'AccessRevoked': {
        const p = payload as any;
        await this.readRepo.update(
          { aggregateId },
          {
            status: 'REVOKED',
            revokedFrom: p.revokedFrom,
            revokedBy: p.revokedBy,
            revocationReason: p.reason ?? null,
            version,
          },
        );
        break;
      }
      default:
        return;
    }

    await this.checkpointRepo.upsert(
      { projectorName: ACCESS_GRANT_PROJECTOR, lastProcessedVersion: globalVersion },
      ['projectorName'],
    );
  }
}
