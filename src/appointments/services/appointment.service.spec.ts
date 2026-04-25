import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { JwtService } from '@nestjs/jwt';
import { BadRequestException, ForbiddenException, NotFoundException } from '@nestjs/common';
import { AppointmentService } from './appointment.service';
import { Appointment, AppointmentStatus, AppointmentType, MedicalPriority } from '../entities/appointment.entity';
import { DoctorAvailability } from '../entities/doctor-availability.entity';

const PATIENT_ID = 'patient-1';
const DOCTOR_ID = 'doctor-1';
const APPOINTMENT_ID = 'appt-1';
const ROOM_ID = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';

const makeAppointment = (overrides: Partial<Appointment> = {}): Appointment =>
  ({
    id: APPOINTMENT_ID,
    patientId: PATIENT_ID,
    doctorId: DOCTOR_ID,
    isTelemedicine: true,
    telemedicineRoomId: ROOM_ID,
    telemedicineLink: `https://telemedicine.app/room/${ROOM_ID}`,
    appointmentDate: new Date(Date.now() + 5 * 60_000), // 5 min from now
    duration: 30,
    status: AppointmentStatus.SCHEDULED,
    type: AppointmentType.TELEMEDICINE,
    priority: MedicalPriority.NORMAL,
    ...overrides,
  } as Appointment);

describe('AppointmentService – telemedicine security', () => {
  let service: AppointmentService;
  let appointmentRepo: { findOne: jest.Mock; create: jest.Mock; save: jest.Mock; find: jest.Mock; count: jest.Mock; createQueryBuilder: jest.Mock };
  let availabilityRepo: { findOne: jest.Mock };
  let jwtService: { sign: jest.Mock };

  beforeEach(async () => {
    const qb = {
      addSelect: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnThis(),
      getOne: jest.fn(),
    };

    appointmentRepo = {
      findOne: jest.fn(),
      create: jest.fn(),
      save: jest.fn(),
      find: jest.fn(),
      count: jest.fn(),
      createQueryBuilder: jest.fn().mockReturnValue(qb),
    };
    availabilityRepo = { findOne: jest.fn() };
    jwtService = { sign: jest.fn().mockReturnValue('signed.jwt.token') };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AppointmentService,
        { provide: getRepositoryToken(Appointment), useValue: appointmentRepo },
        { provide: getRepositoryToken(DoctorAvailability), useValue: availabilityRepo },
        { provide: JwtService, useValue: jwtService },
      ],
    }).compile();

    service = module.get<AppointmentService>(AppointmentService);
  });

  describe('create – room ID generation', () => {
    // Use a fixed future date at 10:00 AM to stay within any availability window
    const appointmentDate = new Date();
    appointmentDate.setDate(appointmentDate.getDate() + 1);
    appointmentDate.setHours(10, 0, 0, 0);

    const baseDto = {
      patientId: PATIENT_ID,
      doctorId: DOCTOR_ID,
      appointmentDate: appointmentDate.toISOString(),
      duration: 30,
      type: AppointmentType.TELEMEDICINE,
      priority: MedicalPriority.NORMAL,
      isTelemedicine: true,
    };

    beforeEach(() => {
      availabilityRepo.findOne.mockResolvedValue({
        doctorId: DOCTOR_ID,
        dayOfWeek: appointmentDate.getDay() || 7,
        startTime: '08:00',
        endTime: '18:00',
        isActive: true,
        slotDuration: 30,
      });
      appointmentRepo.count.mockResolvedValue(0);
      appointmentRepo.create.mockImplementation((data) => ({ ...data }));
      appointmentRepo.save.mockImplementation((a) => Promise.resolve(a));
    });

    it('should generate a UUID room ID, not a timestamp', async () => {
      const result = await service.create(baseDto);
      expect(result.telemedicineRoomId).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
      );
    });

    it('should not expose a predictable timestamp in the room URL', async () => {
      const before = Date.now();
      const result = await service.create(baseDto);
      const after = Date.now();
      // The link must not contain any number in the range [before, after]
      const match = result.telemedicineLink?.match(/(\d{13})/);
      if (match) {
        const ts = parseInt(match[1], 10);
        expect(ts < before || ts > after).toBe(true);
      }
      // Positive: link contains the UUID room ID
      expect(result.telemedicineLink).toContain(result.telemedicineRoomId);
    });

    it('should produce unique room IDs for concurrent bookings', async () => {
      const results = await Promise.all(
        Array.from({ length: 20 }, () => service.create(baseDto)),
      );
      const ids = results.map((r) => r.telemedicineRoomId);
      expect(new Set(ids).size).toBe(20);
    });

    it('should not set telemedicineRoomId for non-telemedicine appointments', async () => {
      const result = await service.create({ ...baseDto, isTelemedicine: false });
      expect(result.telemedicineRoomId).toBeNull();
      expect(result.telemedicineLink).toBeNull();
    });
  });

  describe('issueTelemedicineToken', () => {
    const getQb = () => (appointmentRepo.createQueryBuilder as jest.Mock).mock.results[0]?.value;

    it('should issue a signed JWT for the patient', async () => {
      const appt = makeAppointment();
      appointmentRepo.createQueryBuilder.mockReturnValue({
        addSelect: jest.fn().mockReturnThis(),
        where: jest.fn().mockReturnThis(),
        getOne: jest.fn().mockResolvedValue(appt),
      });

      const result = await service.issueTelemedicineToken(APPOINTMENT_ID, PATIENT_ID);

      expect(result.token).toBe('signed.jwt.token');
      expect(result.roomUrl).toContain(ROOM_ID);
      expect(result.roomUrl).toContain('token=signed.jwt.token');
      expect(jwtService.sign).toHaveBeenCalledWith(
        expect.objectContaining({ sub: PATIENT_ID, roomId: ROOM_ID, role: 'patient' }),
        expect.any(Object),
      );
    });

    it('should issue a signed JWT for the doctor with role=doctor', async () => {
      const appt = makeAppointment();
      appointmentRepo.createQueryBuilder.mockReturnValue({
        addSelect: jest.fn().mockReturnThis(),
        where: jest.fn().mockReturnThis(),
        getOne: jest.fn().mockResolvedValue(appt),
      });

      const result = await service.issueTelemedicineToken(APPOINTMENT_ID, DOCTOR_ID);

      expect(jwtService.sign).toHaveBeenCalledWith(
        expect.objectContaining({ role: 'doctor' }),
        expect.any(Object),
      );
      expect(result.token).toBeDefined();
    });

    it('should throw NotFoundException for unknown appointment', async () => {
      appointmentRepo.createQueryBuilder.mockReturnValue({
        addSelect: jest.fn().mockReturnThis(),
        where: jest.fn().mockReturnThis(),
        getOne: jest.fn().mockResolvedValue(null),
      });

      await expect(
        service.issueTelemedicineToken('unknown-id', PATIENT_ID),
      ).rejects.toThrow(NotFoundException);
    });

    it('should throw BadRequestException for non-telemedicine appointment', async () => {
      appointmentRepo.createQueryBuilder.mockReturnValue({
        addSelect: jest.fn().mockReturnThis(),
        where: jest.fn().mockReturnThis(),
        getOne: jest.fn().mockResolvedValue(makeAppointment({ isTelemedicine: false, telemedicineRoomId: null })),
      });

      await expect(
        service.issueTelemedicineToken(APPOINTMENT_ID, PATIENT_ID),
      ).rejects.toThrow(BadRequestException);
    });

    it('should throw ForbiddenException for a non-participant', async () => {
      appointmentRepo.createQueryBuilder.mockReturnValue({
        addSelect: jest.fn().mockReturnThis(),
        where: jest.fn().mockReturnThis(),
        getOne: jest.fn().mockResolvedValue(makeAppointment()),
      });

      await expect(
        service.issueTelemedicineToken(APPOINTMENT_ID, 'stranger-99'),
      ).rejects.toThrow(ForbiddenException);
    });

    it('should throw BadRequestException when requested too early', async () => {
      // Appointment is 60 minutes away – outside the 15-min window
      const appt = makeAppointment({
        appointmentDate: new Date(Date.now() + 60 * 60_000),
      });
      appointmentRepo.createQueryBuilder.mockReturnValue({
        addSelect: jest.fn().mockReturnThis(),
        where: jest.fn().mockReturnThis(),
        getOne: jest.fn().mockResolvedValue(appt),
      });

      await expect(
        service.issueTelemedicineToken(APPOINTMENT_ID, PATIENT_ID),
      ).rejects.toThrow(BadRequestException);
    });

    it('should throw BadRequestException when the session has already ended', async () => {
      const appt = makeAppointment({
        appointmentDate: new Date(Date.now() - 60 * 60_000), // 1 hour ago
        duration: 30,
      });
      appointmentRepo.createQueryBuilder.mockReturnValue({
        addSelect: jest.fn().mockReturnThis(),
        where: jest.fn().mockReturnThis(),
        getOne: jest.fn().mockResolvedValue(appt),
      });

      await expect(
        service.issueTelemedicineToken(APPOINTMENT_ID, PATIENT_ID),
      ).rejects.toThrow(BadRequestException);
    });
  });
});
