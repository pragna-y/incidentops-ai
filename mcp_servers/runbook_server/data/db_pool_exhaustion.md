# SRE Runbook: DB Connection Pool Exhaustion

**Scenario ID:** `db_pool_exhaustion`
**Severity:** CRITICAL
**Affected Components:** Database connection pool, API gateway, order service
**Runbook Version:** 2.1 | Last reviewed: 2024-01

---

## Overview

A DB connection pool exhaustion event occurs when all available JDBC/HikariCP
connections are held by active threads and new requests cannot acquire a
connection within the timeout window. This cascades across all services that
depend on the database, leading to 503 errors, retry storms, and potential
data consistency issues if retry logic is not idempotent.

**Key Metrics to Monitor:**
| Metric | Warning | Critical |
|--------|---------|----------|
| Pool utilisation | > 80% | > 95% |
| Connection wait time (avg) | > 500ms | > 2000ms |
| Error rate (5xx) | > 5/min | > 20/min |
| P99 API latency | > 500ms | > 2000ms |

---

## Diagnosis

### Step 1: Confirm pool exhaustion
```bash
# Check HikariCP metrics via JMX or application metrics endpoint
curl http://<db-service-host>:8080/actuator/metrics/hikaricp.connections.active

# Check for error logs
kubectl logs -n production deployment/db-service --tail=200 | grep -i "hikari\|pool\|connection"
```

**Expected output when exhausted:**
```
HikariPool-ProductionPool - Connection is not available, request timed out after 30000ms.
```

### Step 2: Identify the cause
Common causes in order of frequency:
1. **Traffic spike** — sudden load increase beyond pool capacity
2. **Slow queries** — long-running transactions hold connections
3. **Connection leak** — connections not properly closed in error paths
4. **Deadlock** — transactions waiting for each other indefinitely

```bash
# Find long-running queries (PostgreSQL)
SELECT pid, now() - pg_stat_activity.query_start AS duration, query, state
FROM pg_stat_activity
WHERE (now() - pg_stat_activity.query_start) > interval '5 minutes'
ORDER BY duration DESC;

# Find idle connections holding slots
SELECT count(*) FROM pg_stat_activity WHERE state = 'idle in transaction';
```

### Step 3: Check downstream impact
```bash
# API Gateway error rate
kubectl logs -n production deployment/api-gateway --tail=100 | grep -c "503\|timeout"

# Order service retry storm
kubectl logs -n production deployment/order-service | grep "Retry attempt" | tail -20
```

---

## Recovery Steps

### Immediate Mitigation (< 5 minutes)

**Action 1: Increase pool max size (temporary)**
```yaml
# application.yml — hot-reload if supported
spring:
  datasource:
    hikari:
      maximum-pool-size: 100  # increase from 50
      connection-timeout: 60000
```
```bash
kubectl set env deployment/db-service HIKARI_MAX_POOL_SIZE=100 -n production
kubectl rollout status deployment/db-service -n production
```

**Action 2: Terminate idle/stale connections**
```sql
-- PostgreSQL: terminate idle connections older than 10 minutes
SELECT pg_terminate_backend(pid)
FROM pg_stat_activity
WHERE state = 'idle'
  AND query_start < now() - interval '10 minutes'
  AND pid <> pg_backend_pid();
```

**Action 3: Enable connection queue with bounded timeout**
```yaml
spring.datasource.hikari:
  connection-timeout: 5000      # Fail fast: 5s instead of 30s
  initialization-fail-timeout: 1
```

### Short-term Fix (< 30 minutes)

**Action 4: Restart affected pods to flush stale connections**
```bash
kubectl rollout restart deployment/db-service -n production
kubectl rollout restart deployment/order-service -n production
```

**Action 5: Enable read replica routing for read-only queries**
```bash
# Route SELECT queries to read replica to reduce primary load
kubectl set env deployment/api-gateway DB_READ_REPLICA_URL=jdbc:postgresql://<replica>:5432/db
```

### Long-term Fix (next sprint)

- Implement connection pool per service (avoid shared pool)
- Add HikariCP metrics to Prometheus + alert at 80% utilisation
- Implement circuit breaker pattern on all DB-dependent services
- Conduct load test to validate new pool sizing

---

## Escalation

Escalate to the database team if:
- Pool exhaustion persists after pool resize + pod restart
- Long-running transactions cannot be killed (blocking DDL operations)
- Read replica is also saturated

**On-call contact:** `#sre-oncall` Slack | PagerDuty escalation policy: `db-critical`

---

## Post-Incident Checklist

- [ ] Root cause identified (traffic spike / slow query / leak / deadlock)
- [ ] Pool size adjusted to accommodate expected peak load
- [ ] Alerting configured at 80% pool utilisation
- [ ] Runbook updated with any new findings
- [ ] Post-mortem scheduled within 48 hours
