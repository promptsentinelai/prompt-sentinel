# 📊 PromptSentinel Monitoring Stack

Complete monitoring solution for PromptSentinel using Prometheus, Grafana, and Loki.

## 🚀 Quick Start

### 1. Start the Monitoring Stack

```bash
# From the monitoring directory
cd monitoring
docker-compose -f docker-compose.monitoring.yml up -d

# Or use the Makefile from project root
make monitoring-up
```

### 2. Access Dashboards

- **Grafana**: http://localhost:3000 (admin/admin)
- **Prometheus**: http://localhost:9090
- **AlertManager**: http://localhost:9093

### 3. Import Dashboards

Dashboards are automatically provisioned. Available dashboards:

1. **PromptSentinel Overview** - Main metrics and KPIs
2. **PromptSentinel Performance** - Latency, throughput, and resource usage
3. **PromptSentinel Security** - Threat detection and security events

## 📈 Metrics Collected

### Application Metrics
- Request rate and latency (P50, P90, P95, P99)
- Detection verdicts (allow, block, flag, strip, redact)
- Detection categories (injection, jailbreak, PII, etc.)
- Cache hit/miss rates
- Provider performance and failures
- API costs and budget usage
- Rate limiting statistics
- WebSocket connections

### System Metrics
- CPU and memory usage
- Disk I/O
- Network traffic
- Container statistics

### Security Metrics
- Threat detection rate
- PII exposure attempts
- Attack patterns and categories
- Critical security events
- Confidence score distribution

## 🔔 Alerts

Pre-configured alerts for:

### Performance
- High response time (>500ms P95)
- Very high response time (>2s P95)
- Low cache hit rate (<50%)

### Security
- High threat detection rate (>20%)
- Critical threats detected
- PII data exposure attempts

### Budget
- Budget warning (>75% usage)
- Budget critical (>90% usage)
- Budget exceeded (blocking active)

### System
- High memory usage (>512MB)
- High CPU usage (>80%)
- Service down
- Provider failures

## 🛠️ Configuration

### Custom Metrics

Add custom metrics to your application:

```python
from prometheus_client import Counter, Histogram, Gauge

# Counter for events
my_counter = Counter('promptsentinel_custom_total', 'Description')
my_counter.inc()

# Histogram for timing
my_histogram = Histogram('promptsentinel_custom_seconds', 'Description')
with my_histogram.time():
    # Your code here
    pass

# Gauge for current values
my_gauge = Gauge('promptsentinel_custom_current', 'Description')
my_gauge.set(42)
```

### Custom Dashboards

1. Create dashboard in Grafana UI
2. Export as JSON
3. Save to `monitoring/grafana/dashboards/`
4. Restart Grafana container

### Custom Alerts

Edit `monitoring/prometheus/alerts/promptsentinel-alerts.yml`:

```yaml
- alert: MyCustomAlert
  expr: my_metric > threshold
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "Alert summary"
    description: "Detailed description"
```

## 📝 Query Examples

### Prometheus Queries

```promql
# Request rate
sum(rate(promptsentinel_requests_total[5m]))

# P95 latency
histogram_quantile(0.95, sum(rate(promptsentinel_request_duration_seconds_bucket[5m])) by (le))

# Detection rate by verdict
sum by (verdict) (rate(promptsentinel_detections_total[5m]))

# Cache hit rate
sum(rate(promptsentinel_cache_hits_total[5m])) / 
(sum(rate(promptsentinel_cache_hits_total[5m])) + sum(rate(promptsentinel_cache_misses_total[5m])))

# Budget usage percentage
promptsentinel_budget_usage_hourly_usd / promptsentinel_budget_limit_hourly_usd * 100

# Top 10 detection patterns
topk(10, sum by (pattern) (increase(promptsentinel_pattern_matches_total[1h])))
```

### Loki Queries (Logs)

```logql
# All security events
{job="promptsentinel"} |~ "block|threat|attack"

# Critical threats
{job="promptsentinel"} |= "severity=critical"

# PII detections
{job="promptsentinel"} |= "pii_detected"

# Errors
{job="promptsentinel"} |= "error"
```

## 🔧 Troubleshooting

### No metrics appearing

1. Check PromptSentinel is exposing metrics:
   ```bash
   curl http://localhost:8080/metrics
   ```

2. Check Prometheus targets:
   - Go to http://localhost:9090/targets
   - Ensure all targets are "UP"

3. Check network connectivity:
   ```bash
   docker network ls
   docker network inspect promptsentinel_default
   ```

### Dashboards not loading

1. Check Grafana datasources:
   - Go to Configuration → Data Sources
   - Test connection to Prometheus

2. Check dashboard provisioning:
   ```bash
   docker logs grafana
   ```

3. Re-import dashboards manually:
   - Go to Dashboards → Import
   - Upload JSON files from `monitoring/grafana/dashboards/`

### Alerts not firing

1. Check alert rules:
   ```bash
   curl http://localhost:9090/api/v1/rules
   ```

2. Check AlertManager configuration:
   ```bash
   docker logs alertmanager
   ```

3. Test alert routing:
   ```bash
   amtool alert add test severity=critical
   ```

## 📊 Production Deployment

### Scaling Considerations

1. **Prometheus Storage**: Configure retention and remote storage
2. **Grafana HA**: Use database backend (MySQL/PostgreSQL)
3. **Log Volume**: Configure Loki retention policies
4. **Alert Routing**: Set up PagerDuty/Slack/Email integrations

### Security

1. **Enable Authentication**: Configure Grafana LDAP/OAuth
2. **Use HTTPS**: Add reverse proxy with SSL
3. **Network Isolation**: Use separate monitoring network
4. **Secrets Management**: Use Docker secrets or Kubernetes secrets

### Backup

```bash
# Backup Prometheus data
docker run --rm -v prometheus_data:/data -v $(pwd):/backup \
  alpine tar czf /backup/prometheus-backup.tar.gz /data

# Backup Grafana dashboards
docker run --rm -v grafana_data:/data -v $(pwd):/backup \
  alpine tar czf /backup/grafana-backup.tar.gz /data

# Backup configurations
tar czf monitoring-config-backup.tar.gz monitoring/
```

## 📚 Resources

- [Prometheus Documentation](https://prometheus.io/docs/)
- [Grafana Documentation](https://grafana.com/docs/)
- [Loki Documentation](https://grafana.com/docs/loki/)
- [AlertManager Documentation](https://prometheus.io/docs/alerting/)