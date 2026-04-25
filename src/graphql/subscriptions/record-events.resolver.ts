import { Resolver, Subscription, Args } from '@nestjs/graphql';
import { MedicalRecord } from '../types/medical-record.type';
import { AccessGrant } from '../types/access-grant.type';
import { GraphqlPubSubService } from '../../pubsub/services/graphql-pubsub.service';

@Resolver()
export class RecordEventsResolver {
  constructor(private readonly pubSub: GraphqlPubSubService) {}

  @Subscription(() => MedicalRecord, {
    filter(payload, variables) {
      return payload.onNewRecord.patientAddress === variables.patientAddress;
    },
    resolve: (payload) => payload.onNewRecord,
  })
  async onNewRecord(
    @Args('patientAddress') patientAddress: string,
  ): Promise<AsyncIterator<MedicalRecord>> {
    return this.pubSub.recordUploadedIterator(patientAddress);
  }

  @Subscription(() => AccessGrant, {
    filter(payload, variables) {
      return payload.onAccessChanged.patientAddress === variables.patientAddress;
    },
    resolve: (payload) => payload.onAccessChanged,
  })
  async onAccessChanged(
    @Args('patientAddress') patientAddress: string,
  ): Promise<AsyncIterator<AccessGrant>> {
    return this.pubSub.accessGrantedIterator(patientAddress);
  }
}
