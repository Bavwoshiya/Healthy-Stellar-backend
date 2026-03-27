import { EventsHandler, IEventHandler } from '@nestjs/cqrs';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { DomainEventPublished } from '../domain-event-published.event';
import { MedicalRecordReadModel } from '../entities/medical-record-read.entity';
import { ProjectionCheckpoint } from '../entities/projection-checkpoint.entity';

export const RECORD_PROJECTOR = 'RecordProjector';

@EventsHandler(DomainEventPublished)
export class RecordProjector implements IEventHandler<DomainEventPublished> {
  constructor(
    @InjectRepository(MedicalRecordReadModel)
    private readonly readRepo: Repository<MedicalRecordReadModel>,
    @InjectRepository(ProjectionCheckpoint)
    private readonly checkpointRepo: Repository<ProjectionCheckpoint>,
  ) {}

  async handle(event: DomainEventPublished): Promise<void> {
    const { domainEvent, globalVersion } = event;
    const { eventType, aggregateId, payload, version } = domainEvent;

    switch (eventType) {
      case 'RecordUploaded': {
        const p = payload as any;
        await this.readRepo.upsert(
          {
            aggregateId,
            patientId: p.patientId,
            recordType: p.recordType,
            cid: p.cid,
            uploadedBy: p.uploadedBy,
            deleted: false,
            version,
          },
          ['aggregateId'],
        );
        break;
      }
      case 'RecordAmended': {
        const p = payload as any;
        await this.readRepo.update(
          { aggregateId },
          { amendedBy: p.amendedBy, lastChanges: p.changes, version },
        );
        break;
      }
      case 'RecordDeleted': {
        await this.readRepo.update({ aggregateId }, { deleted: true, version });
        break;
      }
      default:
        return; // not relevant to this projector
    }

    await this.checkpointRepo.upsert(
      { projectorName: RECORD_PROJECTOR, lastProcessedVersion: globalVersion },
      ['projectorName'],
    );
  }
}
