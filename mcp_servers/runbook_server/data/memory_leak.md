# SRE Runbook: Memory Leak — JVM Heap OOM

**Scenario ID:** `memory_leak`
**Severity:** CRITICAL
**Affected Components:** JVM application, caching layer, container runtime
**Runbook Version:** 2.3 | Last reviewed: 2024-01

---

## Overview

A JVM heap memory leak manifests as steadily increasing heap usage that does
not decrease during garbage collection cycles. Left unmitigated, it results in
`java.lang.OutOfMemoryError: Java heap space`, full GC pauses lasting seconds
(causing request timeouts), and eventual container OOM-kill by the Kubernetes
runtime. The issue is often caused by growing in-memory caches, retained event
listeners, classloader leaks, or unbounded collection growth.

**Key Metrics to Monitor:**
| Metric | Warning | Critical |
|--------|---------|----------|
| JVM heap utilisation | > 75% | > 90% |
| GC pause time (P99) | > 500ms | > 2000ms |
| GC collections per minute | > 5 | > 15 |
| Old-gen heap growth (5m) | > 10% | > 25% |
| Container memory utilisation | > 80% | > 95% |

---

## Diagnosis

### Step 1: Confirm heap growth trend
```bash
# JVM heap metrics (Spring Boot Actuator / Micrometer)
curl http://<app-host>:8080/actuator/metrics/jvm.memory.used?tag=area:heap
curl http://<app-host>:8080/actuator/metrics/jvm.gc.pause

# Kubernetes container memory
kubectl top pods -n production --containers | grep cache-service

# GC log analysis (if enabled)
kubectl logs -n production deployment/cache-service | grep -i "gc\|heap\|oom" | tail -50
```

**Signs of a memory leak (vs. normal GC):**
- Heap usage sawtooth pattern rising between GC cycles
- Old generation growing monotonically
- Full GC triggered more than 3 times per minute
- `G1 Humongous allocation` warnings

### Step 2: Capture a heap dump for analysis
```bash
# Trigger heap dump inside running pod
kubectl exec -n production <pod-name> -- \
  jcmd 1 GC.heap_dump /tmp/heap-$(date +%s).hprof

# Copy heap dump to local machine
kubectl cp production/<pod-name>:/tmp/heap-*.hprof ./heap-dump.hprof

# Open with Eclipse MAT or VisualVM for leak analysis
# Look for: Leak Suspects, Dominator Tree, retained heap > 100MB objects
```

### Step 3: Identify the leak source
Common leak patterns and diagnostic queries:
```bash
# Unbounded Caffeine/Guava cache
curl http://<app-host>:8080/actuator/caches  # View all cache stats

# Check for retained event listeners
jcmd 1 GC.class_stats | sort -rn -k 3 | head -20

# Check for classloader leaks (common in hot-reload scenarios)
jcmd 1 VM.classloaders
```

---

## Recovery Steps

### Immediate Mitigation (< 5 minutes)

**Action 1: Trigger emergency full GC (temporary relief)**
```bash
# Attempt GC via JMX / actuator (may not help if old-gen is full)
curl -X POST http://<app-host>:8080/actuator/gc

# Via jcmd
kubectl exec -n production <pod-name> -- jcmd 1 GC.run
```

**Action 2: Rotate / restart the affected pod (controlled restart)**
```bash
# Rolling restart — Kubernetes will drain and replace pods one by one
kubectl rollout restart deployment/cache-service -n production
kubectl rollout status deployment/cache-service -n production
```
> This provides immediate relief but does not fix the root cause.

**Action 3: Increase JVM heap temporarily (buy time)**
```bash
kubectl set env deployment/cache-service \
  JAVA_TOOL_OPTIONS="-Xms2g -Xmx6g -XX:+UseG1GC -XX:MaxGCPauseMillis=200" \
  -n production
```

### Short-term Fix (< 30 minutes)

**Action 4: Evict and bound the in-memory cache**
```bash
# If the leak is a Caffeine cache with no TTL
kubectl set env deployment/cache-service \
  CACHE_MAXIMUM_SIZE=10000 \
  CACHE_EXPIRE_AFTER_WRITE_MINUTES=30 \
  -n production
```

**Action 5: Enable heap dump on OOM for future incidents**
```bash
kubectl set env deployment/cache-service \
  JAVA_TOOL_OPTIONS="-XX:+HeapDumpOnOutOfMemoryError -XX:HeapDumpPath=/tmp/oom.hprof" \
  -n production
```

**Action 6: Scale down cache replica and add memory limits**
```bash
kubectl patch deployment cache-service -n production --patch '
spec:
  template:
    spec:
      containers:
      - name: cache-service
        resources:
          requests:
            memory: "2Gi"
          limits:
            memory: "5Gi"
'
```

### Long-term Fix (next sprint)

- Analyse heap dump with Eclipse Memory Analyzer (MAT)
- Identify and fix the retaining object path
- Replace unbounded caches with LRU/TTL-bounded caches (Caffeine)
- Add JVM heap Prometheus metrics and alert at 75% sustained
- Implement memory profiling in CI pipeline (allocation profiler)

---

## Escalation

Escalate to the JVM performance team if:
- Heap dump analysis does not identify a clear leak candidate
- The leak reproduces immediately after restart (data-driven leak)
- Multiple services are affected simultaneously (dependency leak)

**On-call contact:** `#jvm-perf-oncall` Slack | PagerDuty escalation policy: `memory-critical`

---

## Post-Incident Checklist

- [ ] Heap dump captured and stored in incident artefacts bucket
- [ ] Root cause identified via MAT analysis
- [ ] Cache bounded with TTL and max-size
- [ ] GC pause alerting configured
- [ ] Memory limit set on container spec
- [ ] Regression test added to CI covering the leak scenario
- [ ] Post-mortem scheduled within 48 hours
