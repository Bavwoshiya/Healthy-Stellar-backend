import { EventsHandler, IEventHandler } from '@nestjs/cqrs';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { DomainEventPublished } from '../domain-event-published.event';
import { AnalyticsSnapshot } from '../entities/analytics-snapshot.entity';
import { ProjectionCheckpoint } from '../entities/projection-checkpoint.entity';

export const ANALYTICS_PROJECTOR = 'AnalyticsProjector';

const EVENT_COLUMN_MAP: Record<string, keyof AnalyticsSnapshot> = {
  RecordUploaded: 'totalRecordsUploaded',
  AccessGranted: 'totalAccessGranted',
  AccessRevoked: 'totalAccessRevoked',
  RecordAmended: 'totalRecordsAmended',
  EmergencyAccessCreated: 'totalEmergencyAccess',
  RecordDeleted: 'totalRecordsDeleted',
};

@EventsHandler(DomainEventPublished)
export class AnalyticsProjector implements IEventHandler<DomainEventPublished> {
  constructor(
    @InjectRepository(AnalyticsSnapshot)
    private readonly snapshotRepo: Repository<AnalyticsSnapshot>,
    @InjectRepository(ProjectionCheckpoint)
    private readonly checkpointRepo: Repository<ProjectionCheckpoint>,
  ) {}

  async handle(event: DomainEventPublished): Promise<void> {
    const { domainEvent, globalVersion } = event;
    const col = EVENT_COLUMN_MAP[domainEvent.eventType];
    if (!col) return;

    const today = new Date().toISOString().slice(0, 10);

    await this.snapshotRepo
      .createQueryBuilder()
      .insert()
      .into(AnalyticsSnapshot)
      .values({ snapshotDate: today })
      .orIgnore()
      .execute();

    await this.snapshotRepo
      .createQueryBuilder()
      .update(AnalyticsSnapshot)
      .set({ [col]: () => `"${col}" + 1` })
      .where('snapshotDate = :today', { today })
      .execute();

    await this.checkpointRepo.upsert(
      { projectorName: ANALYTICS_PROJECTOR, lastProcessedVersion: globalVersion },
      ['projectorName'],
    );
  }
}
