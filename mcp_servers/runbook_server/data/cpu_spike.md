# SRE Runbook: CPU Spike — Thread Exhaustion

**Scenario ID:** `cpu_spike`
**Severity:** HIGH
**Affected Components:** Application servers, thread pools, load balancer
**Runbook Version:** 1.8 | Last reviewed: 2024-01

---

## Overview

A CPU spike with thread exhaustion occurs when the application's thread pool
is saturated, typically caused by slow or blocked I/O operations holding
threads while the system attempts to handle incoming requests. This leads
to high CPU context-switching overhead, elevated P99 latency, and eventually
request queuing and 503 errors as the load balancer cannot route to healthy
backends.

**Key Metrics to Monitor:**
| Metric | Warning | Critical |
|--------|---------|----------|
| CPU utilisation | > 70% | > 90% |
| Thread pool active | > 80% capacity | 100% (saturated) |
| Load average (1m) | > 4.0 | > 8.0 |
| P99 API latency | > 1000ms | > 5000ms |
| 5xx error rate | > 10/min | > 50/min |

---

## Diagnosis

### Step 1: Confirm CPU spike and thread exhaustion
```bash
# Check current CPU utilisation per node
kubectl top nodes
kubectl top pods -n production --sort-by=cpu

# Get thread pool metrics (Spring Boot Actuator)
curl http://<app-host>:8080/actuator/metrics/executor.active
curl http://<app-host>:8080/actuator/metrics/executor.pool.size

# View thread dump (identify blocked threads)
kubectl exec -n production <pod-name> -- kill -3 1  # JVM thread dump to stdout
kubectl logs <pod-name> -n production | grep -A 5 "BLOCKED\|WAITING"
```

### Step 2: Identify blocking operations
```bash
# Find which endpoints are slowest
kubectl logs -n production deployment/api-gateway | grep "latency" | sort -t= -k2 -rn | head -20

# Check for external service timeouts
kubectl logs -n production deployment/payment-service | grep -i "timeout\|slow\|blocked"
```

**Common blocking patterns:**
- Synchronous HTTP calls to slow external services
- Database queries without proper indexing
- Mutex contention on shared data structures
- Log I/O on a slow filesystem

### Step 3: Determine if it's a sustained or transient spike
```bash
# CPU trend over last 30 minutes
# (via Prometheus if available)
curl "http://prometheus:9090/api/v1/query_range?query=rate(process_cpu_seconds_total[5m])&start=$(date -d '30 minutes ago' +%s)&end=$(date +%s)&step=60"
```

---

## Recovery Steps

### Immediate Mitigation (< 5 minutes)

**Action 1: Reduce incoming traffic — enable rate limiting**
```bash
# Increase drop threshold on load balancer
kubectl annotate ingress api-ingress -n production \
  nginx.ingress.kubernetes.io/limit-rps="100"

# Or if using Istio
kubectl apply -f - <<EOF
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: ratelimit-filter
spec:
  configPatches:
  - applyTo: HTTP_FILTER
    # ... rate limit configuration
EOF
```

**Action 2: Scale out application tier horizontally**
```bash
kubectl scale deployment/api-server -n production --replicas=6  # from 3
kubectl rollout status deployment/api-server -n production
```

**Action 3: Increase thread pool size (if headroom exists)**
```bash
kubectl set env deployment/api-server \
  SERVER_TOMCAT_THREADS_MAX=400 \
  SERVER_TOMCAT_THREADS_MIN=100 \
  -n production
```

### Short-term Fix (< 30 minutes)

**Action 4: Identify and kill runaway threads / processes**
```bash
# Find top CPU-consuming processes inside container
kubectl exec -n production <pod-name> -- top -b -n 1 | head -20

# JVM: enable thread CPU time monitoring
kubectl exec -n production <pod-name> -- \
  jcmd 1 VM.native_memory summary
```

**Action 5: Circuit-break slow external dependencies**
```bash
# Temporarily disable non-critical external calls
kubectl set env deployment/api-server \
  FEATURE_PAYMENT_ASYNC=true \
  FEATURE_ANALYTICS_DISABLED=true \
  -n production
```

**Action 6: Restart affected pods (rolling)**
```bash
kubectl rollout restart deployment/api-server -n production
```

### Long-term Fix (next sprint)

- Profile application with async profiler to find CPU hotspots
- Migrate blocking I/O calls to reactive / async patterns
- Implement adaptive concurrency limiting (Concurrency Limiter pattern)
- Add CPU-based HPA (Horizontal Pod Autoscaling)
- Establish baseline CPU profiles and anomaly detection

---

## Escalation

Escalate to the platform engineering team if:
- CPU spike persists after horizontal scaling
- Thread dump shows widespread deadlocks
- Spike is caused by a dependency outside the application tier

**On-call contact:** `#platform-oncall` Slack | PagerDuty escalation policy: `app-critical`

---

## Post-Incident Checklist

- [ ] Root cause identified (which service / operation was blocking)
- [ ] Thread pool sizing reviewed against load profile
- [ ] CPU-based HPA configured
- [ ] Slow external dependencies catalogued with circuit breakers
- [ ] Profiling session scheduled for the next sprint
- [ ] Post-mortem scheduled within 48 hours
