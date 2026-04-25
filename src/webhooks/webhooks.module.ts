import { Module, NestModule, MiddlewareConsumer, RequestMethod } from '@nestjs/common';
import { WebhooksController } from './webhooks.controller';
import { WebhookSignatureMiddleware } from '../common/middleware/webhook-signature.middleware';
import { RawBodyMiddleware } from '../common/middleware/raw-body.middleware';

@Module({
  controllers: [WebhooksController],
})
export class WebhooksModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    // Raw body must run first on all webhook routes so HMAC has the original bytes
    consumer.apply(RawBodyMiddleware).forRoutes(WebhooksController);

    // IPFS webhook — verified with IPFS_WEBHOOK_SECRET
    consumer
      .apply(new WebhookSignatureMiddleware('IPFS_WEBHOOK_SECRET') as any)
      .forRoutes({ path: 'webhooks/ipfs', method: RequestMethod.POST });

    // Stellar webhook — verified with STELLAR_WEBHOOK_SECRET
    consumer
      .apply(new WebhookSignatureMiddleware('STELLAR_WEBHOOK_SECRET') as any)
      .forRoutes({ path: 'webhooks/stellar', method: RequestMethod.POST });
  }
}
