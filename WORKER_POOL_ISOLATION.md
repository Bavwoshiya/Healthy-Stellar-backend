# Worker Pool Isolation - Preventing Starvation

## Problem Statement

Shared worker pools can be starved by one noisy workload. In the original implementation, all BullMQ queue processors ran in the same Node.js process as the main HTTP application, sharing the same event loop and thread pool. This created a risk where:

- Long-running blockchain operations (contract writes) could block other queues
- High-volume notification processing could starve critical medical record operations
- A single queue with many slow jobs could degrade overall system performance

## Solution: Isolated Worker Processes

### Architecture Overview

The solution implements **process-level isolation** for background job processing:

```
┌─────────────────┐    ┌─────────────────┐
│   Main App      │    │   Worker        │
│   (HTTP API)    │    │   Process       │
│                 │    │                 │
│ • API Endpoints │    │ • Queue         │
│ • Controllers   │    │   Processors    │
│ • Bull Board    │    │ • Event         │
│ • Health Checks │    │   Listeners     │
│                 │    │                 │
│ No Processors   │    │ All Processors  │
└─────────────────┘    └─────────────────┘
         │                       │
         └─────── Redis ─────────┘
```

### Implementation Details

#### 1. Dynamic Queue Module
**File**: `src/queues/queue.module.ts`

Modified `QueueModule` to be dynamic with `forRoot(options)`:
- `isWorker: false` - Main app gets queue service and controllers only
- `isWorker: true` - Worker process gets all processors

#### 2. Dedicated Worker Entry Point
**File**: `src/worker.ts`

Standalone application context for job processing:
- No HTTP server
- Graceful shutdown handling
- Process-level isolation

#### 3. Worker Module
**File**: `src/worker.module.ts`

Dedicated module containing:
- All queue processors
- Database connections
- Blockchain services
- Monitoring and tracing

#### 4. Deployment Configuration

**Docker Compose**: Added separate `worker` service
**Package Scripts**: Added worker-specific npm scripts
**Build Config**: Updated TypeScript compilation to include worker.ts

### Benefits

#### 1. Resource Isolation
- Main HTTP application unaffected by job processing load
- Worker processes can be scaled independently
- Memory and CPU isolation between workloads

#### 2. Improved Reliability
- Worker crashes don't affect API availability
- Individual queue failures are contained
- Better error boundaries

#### 3. Performance Optimization
- Dedicated resources for job processing
- No competition between HTTP requests and background jobs
- Optimized concurrency settings per queue type

#### 4. Operational Flexibility
- Scale workers independently of API servers
- Different resource allocations per service
- Separate monitoring and alerting

### Queue Concurrency Settings

| Queue | Purpose | Concurrency | Rationale |
|-------|---------|-------------|-----------|
| contract-writes | Blockchain operations | 3 | Rate-limited by Stellar network |
| stellar-transactions | Transaction processing | 5 | Moderate load balancing |
| event-indexing | Event processing | 2 | Sequential ordering requirements |
| ipfs-uploads | File uploads | 2 | I/O bound operations |
| email-notifications | Notifications | 5 | High throughput required |
| reports | Report generation | 1 | CPU/memory intensive |

### Monitoring and Observability

#### Bull Board Dashboard
- Available at `/admin/queues` on main application
- Real-time queue monitoring
- Job inspection and manual retry

#### Health Checks
- Main app: HTTP health endpoint
- Worker: Process-level monitoring via Docker

#### Logging
- Structured logging for all job operations
- Distributed tracing across queue operations
- Performance metrics collection

### Deployment Commands

```bash
# Development
npm run start:dev          # Main app with hot reload
npm run start:worker:dev   # Worker with hot reload

# Production
npm run start:prod         # Main app
npm run start:worker:prod  # Worker process

# Docker
docker-compose up app worker  # Both services
```

### Migration Guide

#### From Shared Process
1. Deploy worker service alongside existing app
2. Monitor queue performance for 24-48 hours
3. Gradually reduce main app resources if needed
4. Update monitoring dashboards

#### Rollback Plan
- Temporarily disable worker service
- Re-enable processors in main app (set `isWorker: true` in app.module.ts)
- Monitor for performance regression

### Future Enhancements

#### Horizontal Scaling
- Multiple worker instances per queue type
- Load balancing across worker pools
- Auto-scaling based on queue depth

#### Priority Queues
- Job priority levels (critical, normal, low)
- Weighted fair queuing
- SLA-based scheduling

#### Resource Limits
- Per-queue CPU/memory limits
- Circuit breakers for external services
- Adaptive concurrency based on system load

This implementation provides robust protection against workload starvation while maintaining operational simplicity and monitoring capabilities.