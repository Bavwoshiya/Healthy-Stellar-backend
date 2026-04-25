# Distributed Tracing with OpenTelemetry

This document describes the distributed tracing implementation for the Healthy Stellar backend using OpenTelemetry.

## Overview

Distributed tracing has been implemented to provide end-to-end visibility across:
- HTTP requests and responses
- Database queries (PostgreSQL)
- Redis operations
- BullMQ job processing
- Stellar blockchain RPC calls
- IPFS operations
- FHIR resource transformations

## Architecture

### Components

1. **OpenTelemetry SDK** (`src/tracing.ts`)
   - Initializes tracing before application bootstrap
   - Configures auto-instrumentation for HTTP, PostgreSQL, Redis, BullMQ
   - Exports traces to OTLP-compatible collectors (Jaeger, Grafana Tempo, etc.)
   - Implements parent-based sampling for better trace propagation
   - Configurable batch processing with retry logic

2. **TracingService** (`src/common/services/tracing.service.ts`)
   - Utility service for creating custom spans
   - Provides methods for adding attributes, events, and exceptions
   - Supports both async and sync span creation
   - Accessible throughout the application via dependency injection
   - Methods:
     - `withSpan()` - Create async span with automatic error handling
     - `withSpanSync()` - Create sync span
     - `getCurrentTraceId()` - Get current trace ID
     - `getCurrentSpanId()` - Get current span ID
     - `getCurrentTraceContext()` - Get full trace context
     - `addAttributes()` - Add custom attributes to current span
     - `addEvent()` - Record events in current span
     - `recordException()` - Record exceptions with status
     - `setStatus()` - Set span status
     - `getTraceContext()` - Get W3C trace context for propagation

3. **TracingInterceptor** (`src/common/interceptors/tracing.interceptor.ts`)
   - Adds `X-Trace-ID` and `X-Span-ID` headers to all HTTP responses
   - Attaches trace ID and span ID to request object for logging
   - Records HTTP method, URL, status code, and user info in spans
   - Handles both success and error cases

4. **RequestContextMiddleware** (`src/common/middleware/request-context.middleware.ts`)
   - Stores request/trace IDs in AsyncLocalStorage for context propagation
   - Integrates with OpenTelemetry span context
   - Propagates tenant and user information
   - Ensures trace context is available throughout request lifecycle

5. **Custom Instrumentation**
   - **StellarService**: Traces blockchain operations with network details, transaction hashes, and ledger info
   - **IpfsService**: Traces file uploads/downloads with buffer size, CID, and duration
   - **FhirMapperService**: Traces FHIR resource transformations
   - **QueueService**: Propagates trace context across job boundaries
   - **Job Processors**: Extract and continue traces from job data

## Configuration

### Environment Variables

```bash
# Service identification
OTEL_SERVICE_NAME=healthy-stellar-backend

# OTLP Exporter endpoint
# Development (Jaeger): http://localhost:4318/v1/traces
# Production: Your OTLP collector endpoint
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318/v1/traces

# Optional: OTLP exporter headers (JSON string)
OTEL_EXPORTER_OTLP_HEADERS={"Authorization":"Bearer token"}

# Optional: OTLP exporter timeout in milliseconds (default: 10000)
OTEL_EXPORTER_OTLP_TIMEOUT=10000

# Sampling rate (0.0 to 1.0)
# Development: 1.0 (100% - trace everything)
# Production: 0.1 (10% - sample 10% of requests)
OTEL_SAMPLING_RATE=1.0

# Enable/disable tracing
OTEL_TRACING_ENABLED=true
```

### Sampling Strategy

- **Development**: 100% sampling (`OTEL_SAMPLING_RATE=1.0`)
- **Production**: 10% sampling (`OTEL_SAMPLING_RATE=0.1`) to reduce overhead
- Uses parent-based sampler for better trace propagation across service boundaries

## Local Development with Jaeger

### Starting Jaeger

```bash
# Start all development services including Jaeger
docker-compose -f docker-compose.dev.yml up -d

# Jaeger UI will be available at:
# http://localhost:16686
```

### Jaeger Ports

- **16686**: Jaeger UI
- **4318**: OTLP HTTP endpoint (used by the application)
- **4317**: OTLP gRPC endpoint
- **14268**: Jaeger collector HTTP
- **9411**: Zipkin compatible endpoint

## Using Traces

### Viewing Traces in Jaeger

1. Open http://localhost:16686
2. Select service: `healthy-stellar-backend`
3. Click "Find Traces"
4. Click on a trace to see the full span tree

### Trace Context Propagation

Traces are automatically propagated across:

1. **HTTP Requests**: Via standard W3C trace context headers
2. **BullMQ Jobs**: Via `traceContext` field in job data
3. **Database Queries**: Via auto-instrumentation
4. **Redis Operations**: Via auto-instrumentation

### Custom Spans

Use `TracingService` to create custom spans:

```typescript
import { TracingService } from '../common/services/tracing.service';
import { SpanKind } from '@opentelemetry/api';

@Injectable()
export class MyService {
  constructor(private readonly tracingService: TracingService) {}

  async myOperation() {
    return this.tracingService.withSpan(
      'my.operation',
      async (span) => {
        // Add custom attributes
        span.setAttribute('operation.type', 'custom');
        span.setAttribute('user.id', userId);
        
        // Add events
        this.tracingService.addEvent('operation.started', { userId });
        
        // Your business logic
        const result = await this.doWork();
        
        this.tracingService.addEvent('operation.completed', { result });
        return result;
      },
      { 'operation.type': 'custom' }, // Initial attributes
      SpanKind.INTERNAL, // Span kind
    );
  }

  // Synchronous span example
  processData(data: any) {
    return this.tracingService.withSpanSync(
      'data.processing',
      (span) => {
        span.setAttribute('data.size', data.length);
        return this.transform(data);
      },
    );
  }
}
```

### Stellar Blockchain Tracing

All Stellar operations are automatically traced:

```typescript
// These operations create spans with blockchain-specific attributes
await stellarService.anchorRecord(patientId, cid);
// Span: stellar.anchorRecord
// Attributes: patient_id, cid, network, contract_id, tx_hash, ledger

await stellarService.grantAccess(patientId, granteeId, recordId, expiresAt);
// Span: stellar.grantAccess
// Attributes: patient_id, grantee_id, record_id, expires_at, tx_hash

await stellarService.revokeAccess(patientId, granteeId, recordId);
// Span: stellar.revokeAccess
// Attributes: patient_id, grantee_id, record_id, tx_hash

await stellarService.verifyAccess(requesterId, recordId);
// Span: stellar.verifyAccess
// Attributes: requester_id, record_id, has_access, expires_at
```

### IPFS Operations Tracing

IPFS operations are traced with performance metrics:

```typescript
// Fetch operation
const blob = await ipfsService.fetch(cid);
// Span: ipfs.fetch
// Attributes: cid, gateway, payload_size, fetch_duration_ms, http_status_code

// Upload operation
const cid = await ipfsService.upload(content, metadata);
// Span: ipfs.upload
// Attributes: content_size, cid, upload_duration_ms
```

## Trace ID in Logs

All logs include the trace ID for correlation:

```
[StellarService][traceId: 5f9c8d7e6b4a3c2d1e0f9a8b] CID anchored on Stellar: abc123
```

The trace ID is automatically extracted from the OpenTelemetry context and included in structured logs via Pino.

## Trace ID in HTTP Responses

Every HTTP response includes trace context headers:

```
X-Trace-ID: 5f9c8d7e6b4a3c2d1e0f9a8b
X-Span-ID: 1a2b3c4d5e6f7g8h
```

This allows clients to reference specific traces when reporting issues.

## Production Deployment

### OTLP Collector Options

1. **Jaeger**: Self-hosted or managed
   ```yaml
   OTEL_EXPORTER_OTLP_ENDPOINT=http://jaeger-collector:4318/v1/traces
   ```

2. **Grafana Tempo**: Open-source, S3-backed
   ```yaml
   OTEL_EXPORTER_OTLP_ENDPOINT=http://tempo:4318/v1/traces
   ```

3. **AWS X-Ray**: Via OTLP exporter
   ```yaml
   OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
   ```

4. **Datadog**: Via OTLP exporter
   ```yaml
   OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
   OTEL_EXPORTER_OTLP_HEADERS={"DD-API-KEY":"your-api-key"}
   ```

5. **New Relic**: Via OTLP exporter
   ```yaml
   OTEL_EXPORTER_OTLP_ENDPOINT=https://otlp.nr-data.net:4317
   OTEL_EXPORTER_OTLP_HEADERS={"api-key":"your-api-key"}
   ```

6. **Honeycomb**: Via OTLP exporter
   ```yaml
   OTEL_EXPORTER_OTLP_ENDPOINT=https://api.honeycomb.io:443
   OTEL_EXPORTER_OTLP_HEADERS={"x-honeycomb-team":"your-api-key"}
   ```

### Example: Grafana Tempo

```yaml
# docker-compose.prod.yml
tempo:
  image: grafana/tempo:latest
  command: ["-config.file=/etc/tempo.yaml"]
  volumes:
    - ./tempo.yaml:/etc/tempo.yaml
    - tempo-data:/tmp/tempo
  ports:
    - "4318:4318"  # OTLP HTTP
```

### Performance Considerations

1. **Sampling**: Use 10% sampling in production (`OTEL_SAMPLING_RATE=0.1`)
2. **Batch Processing**: Spans are batched before export (configured in SDK)
   - Max queue size: 2048 spans
   - Max batch size: 512 spans
   - Scheduled delay: 5 seconds
3. **Resource Limits**: Monitor collector resource usage
4. **Retention**: Configure appropriate trace retention policies
5. **Timeout**: Adjust `OTEL_EXPORTER_OTLP_TIMEOUT` based on network latency

## Instrumented Operations

### Automatic Instrumentation

- ✅ HTTP requests/responses (method, URL, status, duration)
- ✅ PostgreSQL queries (statement, rows affected)
- ✅ Redis operations (command, args count)
- ✅ IORedis operations
- ✅ BullMQ job processing

### Custom Instrumentation

- ✅ Stellar blockchain operations
  - Account loading
  - Transaction building and submission
  - Contract invocation
  - Access verification
- ✅ IPFS operations
  - File uploads with buffer size
  - File downloads with duration
- ✅ FHIR transformations
  - Patient mapping
  - DocumentReference mapping
  - Consent mapping
  - Provenance mapping
- ✅ BullMQ job processing
  - Job dispatch with trace context
  - Job processing with trace continuation

## Troubleshooting

### Traces Not Appearing

1. Check OTLP endpoint is accessible:
   ```bash
   curl http://localhost:4318/v1/traces
   ```

2. Verify environment variables are set:
   ```bash
   echo $OTEL_EXPORTER_OTLP_ENDPOINT
   echo $OTEL_SAMPLING_RATE
   echo $OTEL_TRACING_ENABLED
   ```

3. Check application logs for tracing initialization:
   ```
   OpenTelemetry tracing initialized for healthy-stellar-backend (sampling: 100%)
   OTLP Exporter: http://localhost:4318/v1/traces
   ```

4. Verify Jaeger is running:
   ```bash
   docker ps | grep jaeger
   ```

### High Overhead

1. Reduce sampling rate: `OTEL_SAMPLING_RATE=0.1`
2. Disable file system instrumentation (already disabled)
3. Filter out health check endpoints (already configured)
4. Increase batch size for better throughput

### Missing Trace Context in Jobs

Ensure job data includes `traceContext`:

```typescript
const traceContext = this.tracingService.getTraceContext();
const enrichedJobData = {
  ...jobData,
  traceContext,
  traceId: this.tracingService.getCurrentTraceId(),
};
```

### Trace Context Not Propagating

1. Ensure `RequestContextMiddleware` is registered in `AppModule`
2. Check that `TracingInterceptor` is applied globally
3. Verify OpenTelemetry SDK is initialized before app bootstrap
4. Check for context loss in async operations (use `context.with()`)

## Best Practices

1. **Meaningful Span Names**: Use hierarchical naming (e.g., `stellar.anchorCid`, `ipfs.fetch`, `fhir.mapper.toPatient`)
2. **Add Context**: Include relevant attributes (patient ID, operation type, etc.)
3. **Record Events**: Mark important milestones within spans
4. **Handle Errors**: Always record exceptions in spans
5. **Avoid PII**: Don't include sensitive patient data in span attributes
6. **Use Span Kinds**: Specify appropriate span kind (CLIENT, SERVER, INTERNAL, etc.)
7. **Batch Operations**: Group related operations in a single span when possible
8. **Monitor Overhead**: Track tracing overhead in production

## Metrics and Monitoring

Consider adding these metrics alongside tracing:

- Request latency percentiles (p50, p95, p99)
- Error rates by operation type
- Stellar transaction success/failure rates
- IPFS upload/download latency
- Queue processing time
- Trace sampling rate effectiveness

## Integration with Logging

Trace IDs are automatically included in all structured logs via Pino:

```typescript
// Logs will include trace context
this.logger.log('Operation completed', { traceId, spanId, userId });
```

## Integration with Metrics

Prometheus metrics are collected alongside traces:

```typescript
// Metrics are recorded with trace context
this.metricsService.recordDuration('stellar.operation', duration, { operation: 'anchorRecord' });
```

## References

- [OpenTelemetry Documentation](https://opentelemetry.io/docs/)
- [Jaeger Documentation](https://www.jaegertracing.io/docs/)
- [OTLP Specification](https://opentelemetry.io/docs/specs/otlp/)
- [W3C Trace Context](https://www.w3.org/TR/trace-context/)
- [OpenTelemetry Best Practices](https://opentelemetry.io/docs/guides/sampling/)
