// src/queue/email-lookup.service.ts
// Resolves IDs stored in queue payloads to the full objects needed by MailService.
// Inject your actual TypeORM repositories here once entities are wired up.
import { Injectable, NotFoundException } from '@nestjs/common';
import { Patient, Provider, MedicalRecord, SuspiciousAccessEvent } from './mail.service';

@Injectable()
export class EmailLookupService {
  /**
   * Fetch patient contact details by ID.
   * Replace the stub with: this.patientRepository.findOneOrFail({ where: { id } })
   */
  async findPatient(id: string): Promise<Patient> {
    // TODO: inject PatientRepository and query DB
    throw new NotFoundException(`Patient ${id} not found`);
  }

  /**
   * Fetch provider details by ID.
   * Replace the stub with: this.providerRepository.findOneOrFail({ where: { id } })
   */
  async findProvider(id: string): Promise<Provider> {
    // TODO: inject ProviderRepository and query DB
    throw new NotFoundException(`Provider ${id} not found`);
  }

  /**
   * Fetch medical record metadata by ID.
   * Replace the stub with: this.recordRepository.findOneOrFail({ where: { id } })
   */
  async findRecord(id: string): Promise<MedicalRecord> {
    // TODO: inject MedicalRecordRepository and query DB
    throw new NotFoundException(`MedicalRecord ${id} not found`);
  }

  /**
   * Fetch suspicious-access event details by ID.
   * Replace the stub with: this.accessEventRepository.findOneOrFail({ where: { id } })
   */
  async findAccessEvent(id: string): Promise<SuspiciousAccessEvent> {
    // TODO: inject AccessEventRepository and query DB
    throw new NotFoundException(`AccessEvent ${id} not found`);
  }
}
