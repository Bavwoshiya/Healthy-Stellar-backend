import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { EmergencyMedicalInfo } from './entities/emergency-medical-info.entity';
import { EmergencyMedicalInfoService } from './services/emergency-medical-info.service';
import { EmergencyMedicalInfoController } from './controllers/emergency-medical-info.controller';

@Module({
  imports: [TypeOrmModule.forFeature([EmergencyMedicalInfo])],
  controllers: [EmergencyMedicalInfoController],
  providers: [EmergencyMedicalInfoService],
  exports: [EmergencyMedicalInfoService],
})
export class EmergencyMedicalInfoModule {}
