import {
  Column,
  CreateDateColumn,
  Entity,
  Index,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';

export enum BloodType {
  A_POS = 'A+',
  A_NEG = 'A-',
  B_POS = 'B+',
  B_NEG = 'B-',
  AB_POS = 'AB+',
  AB_NEG = 'AB-',
  O_POS = 'O+',
  O_NEG = 'O-',
  UNKNOWN = 'unknown',
}

@Entity('emergency_medical_info')
@Index(['patientId'], { unique: true })
export class EmergencyMedicalInfo {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  patientId: string;

  @Column({ type: 'enum', enum: BloodType, default: BloodType.UNKNOWN })
  bloodType: BloodType;

  @Column({ type: 'text', array: true, default: [] })
  allergies: string[];

  @Column({ type: 'text', array: true, default: [] })
  currentMedications: string[];

  @Column({ type: 'text', array: true, default: [] })
  chronicConditions: string[];

  @Column({ type: 'boolean', default: false })
  dnrStatus: boolean;

  @Column({ type: 'jsonb', nullable: true })
  emergencyContacts: Array<{ name: string; relationship: string; phone: string }>;

  @Column({ type: 'text', nullable: true })
  insuranceInfo: string;

  @Column({ type: 'text', nullable: true })
  additionalNotes: string;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
