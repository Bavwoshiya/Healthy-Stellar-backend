import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { HospitalRegistry } from './entities/hospital-registry.entity';
import { HospitalRegistryService } from './services/hospital-registry.service';
import { HospitalRegistryController } from './controllers/hospital-registry.controller';

@Module({
  imports: [TypeOrmModule.forFeature([HospitalRegistry])],
  controllers: [HospitalRegistryController],
  providers: [HospitalRegistryService],
  exports: [HospitalRegistryService],
})
export class HospitalRegistryModule {}
