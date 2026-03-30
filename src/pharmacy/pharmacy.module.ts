import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { HttpModule } from '@nestjs/axios';
import { Drug } from './entities/drug.entity';
import { Prescription } from './entities/prescription.entity';
import { DrugInteraction } from './entities/drug-interaction.entity';
import { PharmacyController } from './controllers/pharmacy.controller';
import { CdsHooksController } from './controllers/cds-hooks.controller';
import { PharmacyService } from './services/pharmacy.service';
import { DrugInteractionService } from './services/drug-interaction.service';

@Module({
  imports: [
    TypeOrmModule.forFeature([Drug, Prescription, DrugInteraction]),
    HttpModule,
  ],
  controllers: [PharmacyController, CdsHooksController],
  providers: [PharmacyService, DrugInteractionService],
  exports: [PharmacyService, DrugInteractionService],
})
export class PharmacyModule {}
