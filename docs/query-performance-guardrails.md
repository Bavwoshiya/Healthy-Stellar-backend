# Database Query Performance Guardrails

## Overview

This implementation adds comprehensive database query performance guardrails to prevent high-latency queries from degrading core flows under peak load.

## Features

### 1. Request-Level Timeouts
- **QueryPerformanceInterceptor**: Enforces request timeout limits (default: 30s)
- Automatically terminates requests exceeding timeout
- Logs slow requests for analysis

### 2. Database-Level Guardrails
- **Statement Timeout**: Maximum time for single query (default: 10s)
- **Query Timeout**: Maximum time for transaction (default: 30s)
- **Connection Pool Monitoring**: Rejects requests when pool utilization exceeds threshold (default: 80%)

### 3. Query Performance Monitoring
- **QueryPerformanceMonitor**: Tracks and logs slow queries
- **pg_stat_statements**: PostgreSQL extension for query statistics
- **Prometheus Metrics**: Exposes query performance metrics
  - `db_slow_queries_total`: Counter of slow queries by severity
  - `db_query_duration_seconds`: Histogram of query durations

### 4. Database Query Guard
- **DatabaseQueryGuard**: Pre-request validation
- Checks connection pool health
- Sets statement timeout for each request
- Rejects requests when database is under stress

## Configuration

Add these environment variables to your `.env` file:

```bash
# Request timeout in milliseconds (max time for entire HTTP request)
REQUEST_TIMEOUT_MS=30000

# Database statement timeout in milliseconds (max time for single query)
DB_STATEMENT_TIMEOUT_MS=10000

# Database query timeout in milliseconds (max time for transaction)
DB_QUERY_TIMEOUT_MS=30000

# Slow query threshold in milliseconds (log queries exceeding this)
SLOW_QUERY_THRESHOLD_MS=1000

# Critical query threshold in milliseconds (alert on queries exceeding this)
CRITICAL_QUERY_THRESHOLD_MS=5000

# Database pool utilization threshold (0.0-1.0, reject requests above this)
DB_POOL_THRESHOLD=0.8
```

## Usage

### Automatic Protection

All endpoints are automatically protected by the global interceptor:

```typescript
// No code changes needed - protection is automatic
@Get('patients')
async getPatients() {
  // This request will timeout after REQUEST_TIMEOUT_MS
  // Individual queries will timeout after DB_STATEMENT_TIMEOUT_MS
}
```

### Manual Guard Application

For critical endpoints, apply the guard explicitly:

```typescript
@Get('critical-operation')
@UseGuards(DatabaseQueryGuard)
async criticalOperation() {
  // Additional database health checks before execution
}
```

### Monitoring Slow Queries

Access the admin endpoints to monitor query performance:

```bash
# Get slow queries
GET /admin/query-performance/slow-queries?limit=10

# Reset query statistics
POST /admin/query-performance/reset-stats
```

### Prometheus Metrics

Query performance metrics are exposed at `/metrics`:

```promql
# Alert on high slow query rate
rate(db_slow_queries_total[5m]) > 10

# Alert on high query duration
histogram_quantile(0.95, rate(db_query_duration_seconds_bucket[5m])) > 5
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     HTTP Request                             │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│          QueryPerformanceInterceptor                         │
│  • Enforces REQUEST_TIMEOUT_MS                               │
│  • Logs slow requests                                        │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│          DatabaseQueryGuard (Optional)                       │
│  • Checks connection pool health                             │
│  • Sets statement timeout                                    │
│  • Rejects if pool exhausted                                 │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│          Database Query Execution                            │
│  • statement_timeout: DB_STATEMENT_TIMEOUT_MS                │
│  • query_timeout: DB_QUERY_TIMEOUT_MS                        │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│          QueryPerformanceMonitor                             │
│  • Logs slow queries                                         │
│  • Records Prometheus metrics                                │
│  • Alerts on critical queries                                │
└─────────────────────────────────────────────────────────────┘
```

## Migration

Run the migration to enable query monitoring:

```bash
npm run migration:run
```

This enables the `pg_stat_statements` extension for query performance tracking.

## Testing

### Load Testing

Test query performance under load:

```bash
npm run load-test:patient-reads
npm run load-test:provider-writes
```

### Manual Testing

Test timeout behavior:

```sql
-- This query will timeout after DB_STATEMENT_TIMEOUT_MS
SELECT pg_sleep(15);
```

## Monitoring & Alerting

### Recommended Alerts

1. **High Slow Query Rate**
   ```promql
   rate(db_slow_queries_total{severity="critical"}[5m]) > 1
   ```

2. **High Query Duration**
   ```promql
   histogram_quantile(0.95, rate(db_query_duration_seconds_bucket[5m])) > 5
   ```

3. **Connection Pool Exhaustion**
   ```promql
   db_pool_utilization_percent > 80
   ```

### Logs

Slow queries are logged with context:

```json
{
  "level": "warn",
  "message": "Slow query detected",
  "query": "SELECT * FROM medical_record WHERE...",
  "duration": 1500,
  "threshold": 1000,
  "severity": "warning",
  "context": "QueryPerformanceMonitor"
}
```

## Performance Impact

- **Interceptor Overhead**: < 1ms per request
- **Guard Overhead**: < 5ms per request (includes pool health check)
- **Monitoring Overhead**: Negligible (async logging)

## Best Practices

1. **Set Appropriate Timeouts**: Balance between user experience and resource protection
2. **Monitor Slow Queries**: Regularly review slow query logs and optimize
3. **Use Indexes**: Ensure proper indexes on frequently queried columns
4. **Optimize Queries**: Use EXPLAIN ANALYZE to identify bottlenecks
5. **Connection Pool Sizing**: Adjust DB_POOL_MAX based on load testing

## Troubleshooting

### Request Timeouts

If requests are timing out:

1. Check slow query logs
2. Review query execution plans
3. Add missing indexes
4. Increase timeout values if necessary

### Connection Pool Exhaustion

If pool is exhausted:

1. Increase DB_POOL_MAX
2. Reduce DB_IDLE_TIMEOUT_MS
3. Optimize slow queries
4. Scale database resources

## Related Documentation

- [Database Profiling](../docs/database-profiling.md)
- [Performance Optimization](../src/performance/README.md)
- [Load Testing](../load-tests/README.md)
