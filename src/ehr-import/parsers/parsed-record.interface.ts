import { RecordType } from '../../records/dto/create-record.dto';

export interface ParsedRecord {
  patientId: string;
  recordType: RecordType;
  description?: string;
  rawPayload: string;
}
