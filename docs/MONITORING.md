# Monitoring Guide

Comprehensive guide for monitoring PromptSentinel in production environments.

## Table of Contents
- [Overview](#overview)
- [Metrics Collection](#metrics-collection)
- [Prometheus Setup](#prometheus-setup)
- [Grafana Dashboards](#grafana-dashboards)
- [Logging Configuration](#logging-configuration)
- [Distributed Tracing](#distributed-tracing)
- [Alerting Rules](#alerting-rules)
- [Health Checks](#health-checks)
- [Performance Monitoring](#performance-monitoring)
- [Security Monitoring](#security-monitoring)
- [Cost Monitoring](#cost-monitoring)

## Overview

PromptSentinel provides comprehensive monitoring capabilities through:
- **Metrics**: Prometheus-compatible metrics endpoint
- **Logging**: Structured JSON logging with multiple levels
- **Tracing**: OpenTelemetry support for distributed tracing
- **Health Checks**: Liveness and readiness probes
- **Custom Metrics**: Application-specific metrics

### Key Metrics to Monitor

| Metric | Description | Alert Threshold |
|--------|-------------|-----------------|
| Request Rate | Requests per second | >1000 req/s |
| Error Rate | Percentage of failed requests | >5% |
| Latency P95 | 95th percentile response time | >1s |
| Cache Hit Rate | Percentage of cached responses | <50% |
| LLM API Errors | Provider API failures | >10/min |
| Detection Blocks | Security threats blocked | >100/hour |
| Budget Usage | API cost consumption | >80% |

## Metrics Collection

### Built-in Metrics Endpoint

PromptSentinel exposes metrics at `/metrics` in Prometheus format:

```bash
# View raw metrics
curl http://localhost:8080/metrics

# Sample output
# HELP promptsentinel_requests_total Total number of requests
# TYPE promptsentinel_requests_total counter
promptsentinel_requests_total{method="POST",endpoint="/api/v1/detect",status="200"} 1543

# HELP promptsentinel_request_duration_seconds Request duration in seconds
# TYPE promptsentinel_request_duration_seconds histogram
promptsentinel_request_duration_seconds_bucket{le="0.1"} 1200
promptsentinel_request_duration_seconds_bucket{le="0.5"} 1400
promptsentinel_request_duration_seconds_bucket{le="1.0"} 1500
```

### Available Metrics

```yaml
# Core Metrics
promptsentinel_requests_total          # Total requests by endpoint, method, status
promptsentinel_request_duration_seconds # Request latency histogram
promptsentinel_active_connections      # Current active connections
promptsentinel_errors_total            # Total errors by type

# Detection Metrics
promptsentinel_detections_total        # Total detections by verdict
promptsentinel_detection_confidence    # Confidence score distribution
promptsentinel_threats_blocked_total   # Threats blocked by category
promptsentinel_pii_detected_total      # PII detections by type

# Cache Metrics
promptsentinel_cache_hits_total        # Cache hits
promptsentinel_cache_misses_total      # Cache misses
promptsentinel_cache_evictions_total   # Cache evictions
promptsentinel_cache_size_bytes        # Current cache size

# LLM Provider Metrics
promptsentinel_llm_requests_total      # Requests by provider
promptsentinel_llm_tokens_total        # Tokens consumed
promptsentinel_llm_errors_total        # Provider errors
promptsentinel_llm_latency_seconds     # Provider response time

# System Metrics
promptsentinel_memory_usage_bytes      # Memory usage
promptsentinel_cpu_usage_percent       # CPU usage
promptsentinel_goroutines              # Active goroutines (Go)
promptsentinel_open_file_descriptors   # Open file descriptors
```

### Custom Metrics Implementation

```python
# src/prompt_sentinel/monitoring/metrics.py
from prometheus_client import Counter, Histogram, Gauge, Summary
import time

# Define custom metrics
request_counter = Counter(
    'promptsentinel_requests_total',
    'Total number of requests',
    ['method', 'endpoint', 'status']
)

request_duration = Histogram(
    'promptsentinel_request_duration_seconds',
    'Request duration in seconds',
    ['endpoint'],
    buckets=(0.01, 0.05, 0.1, 0.5, 1.0, 2.5, 5.0, 10.0)
)

active_connections = Gauge(
    'promptsentinel_active_connections',
    'Number of active connections'
)

detection_verdict = Counter(
    'promptsentinel_detections_total',
    'Total detections by verdict',
    ['verdict', 'mode']
)

cache_operations = Counter(
    'promptsentinel_cache_operations_total',
    'Cache operations',
    ['operation', 'result']
)

# Decorator for timing functions
def track_time(endpoint):
    def decorator(func):
        def wrapper(*args, **kwargs):
            start = time.time()
            try:
                result = func(*args, **kwargs)
                status = "success"
            except Exception as e:
                status = "error"
                raise
            finally:
                duration = time.time() - start
                request_duration.labels(endpoint=endpoint).observe(duration)
                request_counter.labels(
                    method="POST",
                    endpoint=endpoint,
                    status=status
                ).inc()
            return result
        return wrapper
    return decorator

# Usage in API endpoints
@track_time("/api/v1/detect")
async def detect_endpoint(request):
    # Detection logic
    verdict = perform_detection(request)
    detection_verdict.labels(
        verdict=verdict,
        mode=request.detection_mode
    ).inc()
    return verdict
```

## Prometheus Setup

### Prometheus Configuration

```yaml
# prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s
  external_labels:
    environment: 'production'
    service: 'promptsentinel'

# Alerting configuration
alerting:
  alertmanagers:
    - static_configs:
        - targets: ['alertmanager:9093']

# Load rules
rule_files:
  - "alerts/*.yml"

# Scrape configurations
scrape_configs:
  # PromptSentinel metrics
  - job_name: 'promptsentinel'
    static_configs:
      - targets: ['promptsentinel:8080']
    metrics_path: '/metrics'
    scrape_interval: 10s
    
  # Redis exporter
  - job_name: 'redis'
    static_configs:
      - targets: ['redis-exporter:9121']
    
  # Node exporter for system metrics
  - job_name: 'node'
    static_configs:
      - targets: ['node-exporter:9100']
      
  # Kubernetes service discovery
  - job_name: 'kubernetes-pods'
    kubernetes_sd_configs:
      - role: pod
        namespaces:
          names: ['promptsentinel']
    relabel_configs:
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scrape]
        action: keep
        regex: true
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_path]
        action: replace
        target_label: __metrics_path__
        regex: (.+)
```

### Docker Compose Setup

```yaml
# docker-compose.monitoring.yml
version: '3.8'

services:
  prometheus:
    image: prom/prometheus:latest
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - ./alerts:/etc/prometheus/alerts
      - prometheus-data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/usr/share/prometheus/console_libraries'
      - '--web.console.templates=/usr/share/prometheus/consoles'
      - '--web.enable-lifecycle'
      - '--storage.tsdb.retention.time=30d'
    ports:
      - "9090:9090"
    networks:
      - monitoring
      
  grafana:
    image: grafana/grafana:latest
    volumes:
      - grafana-data:/var/lib/grafana
      - ./grafana/dashboards:/etc/grafana/provisioning/dashboards
      - ./grafana/datasources:/etc/grafana/provisioning/datasources
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
      - GF_INSTALL_PLUGINS=redis-datasource
    ports:
      - "3000:3000"
    networks:
      - monitoring
      
  alertmanager:
    image: prom/alertmanager:latest
    volumes:
      - ./alertmanager.yml:/etc/alertmanager/alertmanager.yml
      - alertmanager-data:/alertmanager
    command:
      - '--config.file=/etc/alertmanager/alertmanager.yml'
      - '--storage.path=/alertmanager'
    ports:
      - "9093:9093"
    networks:
      - monitoring
      
  node-exporter:
    image: prom/node-exporter:latest
    volumes:
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
      - /:/rootfs:ro
    command:
      - '--path.procfs=/host/proc'
      - '--path.sysfs=/host/sys'
      - '--collector.filesystem.mount-points-exclude=^/(sys|proc|dev|host|etc)($$|/)'
    ports:
      - "9100:9100"
    networks:
      - monitoring

volumes:
  prometheus-data:
  grafana-data:
  alertmanager-data:

networks:
  monitoring:
    driver: bridge
```

## Grafana Dashboards

### Main Dashboard JSON

```json
{
  "dashboard": {
    "title": "PromptSentinel Monitoring",
    "timezone": "browser",
    "panels": [
      {
        "id": 1,
        "title": "Request Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(promptsentinel_requests_total[5m])",
            "legendFormat": "{{method}} {{endpoint}}"
          }
        ],
        "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0}
      },
      {
        "id": 2,
        "title": "Error Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(promptsentinel_errors_total[5m]) / rate(promptsentinel_requests_total[5m]) * 100",
            "legendFormat": "Error %"
          }
        ],
        "gridPos": {"h": 8, "w": 12, "x": 12, "y": 0}
      },
      {
        "id": 3,
        "title": "Response Time (P50, P95, P99)",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.5, rate(promptsentinel_request_duration_seconds_bucket[5m]))",
            "legendFormat": "P50"
          },
          {
            "expr": "histogram_quantile(0.95, rate(promptsentinel_request_duration_seconds_bucket[5m]))",
            "legendFormat": "P95"
          },
          {
            "expr": "histogram_quantile(0.99, rate(promptsentinel_request_duration_seconds_bucket[5m]))",
            "legendFormat": "P99"
          }
        ],
        "gridPos": {"h": 8, "w": 12, "x": 0, "y": 8}
      },
      {
        "id": 4,
        "title": "Detection Verdicts",
        "type": "piechart",
        "targets": [
          {
            "expr": "sum by (verdict) (rate(promptsentinel_detections_total[5m]))",
            "legendFormat": "{{verdict}}"
          }
        ],
        "gridPos": {"h": 8, "w": 12, "x": 12, "y": 8}
      },
      {
        "id": 5,
        "title": "Cache Hit Rate",
        "type": "stat",
        "targets": [
          {
            "expr": "rate(promptsentinel_cache_hits_total[5m]) / (rate(promptsentinel_cache_hits_total[5m]) + rate(promptsentinel_cache_misses_total[5m])) * 100",
            "legendFormat": "Hit Rate %"
          }
        ],
        "gridPos": {"h": 4, "w": 6, "x": 0, "y": 16}
      },
      {
        "id": 6,
        "title": "Active Connections",
        "type": "stat",
        "targets": [
          {
            "expr": "promptsentinel_active_connections",
            "legendFormat": "Connections"
          }
        ],
        "gridPos": {"h": 4, "w": 6, "x": 6, "y": 16}
      },
      {
        "id": 7,
        "title": "Memory Usage",
        "type": "gauge",
        "targets": [
          {
            "expr": "promptsentinel_memory_usage_bytes / 1024 / 1024 / 1024",
            "legendFormat": "GB"
          }
        ],
        "gridPos": {"h": 4, "w": 6, "x": 12, "y": 16}
      },
      {
        "id": 8,
        "title": "LLM API Usage",
        "type": "graph",
        "targets": [
          {
            "expr": "sum by (provider) (rate(promptsentinel_llm_requests_total[5m]))",
            "legendFormat": "{{provider}}"
          }
        ],
        "gridPos": {"h": 8, "w": 12, "x": 0, "y": 20}
      },
      {
        "id": 9,
        "title": "Threats Blocked",
        "type": "graph",
        "targets": [
          {
            "expr": "sum by (category) (rate(promptsentinel_threats_blocked_total[5m]))",
            "legendFormat": "{{category}}"
          }
        ],
        "gridPos": {"h": 8, "w": 12, "x": 12, "y": 20}
      }
    ]
  }
}
```

### Security Dashboard

```json
{
  "dashboard": {
    "title": "PromptSentinel Security",
    "panels": [
      {
        "title": "Threat Detection Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(promptsentinel_threats_blocked_total[5m])",
            "legendFormat": "Threats/sec"
          }
        ]
      },
      {
        "title": "Top Threat Categories",
        "type": "table",
        "targets": [
          {
            "expr": "topk(10, sum by (category) (promptsentinel_threats_blocked_total))"
          }
        ]
      },
      {
        "title": "PII Detection",
        "type": "bargauge",
        "targets": [
          {
            "expr": "sum by (type) (promptsentinel_pii_detected_total)",
            "legendFormat": "{{type}}"
          }
        ]
      },
      {
        "title": "Detection Confidence Distribution",
        "type": "heatmap",
        "targets": [
          {
            "expr": "promptsentinel_detection_confidence",
            "format": "heatmap"
          }
        ]
      }
    ]
  }
}
```

## Logging Configuration

### Structured Logging Setup

```python
# src/prompt_sentinel/config/logging.py
import logging
import json
import sys
from datetime import datetime
from pythonjsonlogger import jsonlogger

class CustomJsonFormatter(jsonlogger.JsonFormatter):
    def add_fields(self, log_record, record, message_dict):
        super(CustomJsonFormatter, self).add_fields(log_record, record, message_dict)
        log_record['timestamp'] = datetime.utcnow().isoformat()
        log_record['level'] = record.levelname
        log_record['service'] = 'promptsentinel'
        log_record['environment'] = os.getenv('ENVIRONMENT', 'development')
        
        # Add trace context if available
        if hasattr(record, 'trace_id'):
            log_record['trace_id'] = record.trace_id
        if hasattr(record, 'span_id'):
            log_record['span_id'] = record.span_id

def setup_logging(log_level='INFO'):
    """Configure structured logging."""
    
    # Create logger
    logger = logging.getLogger('promptsentinel')
    logger.setLevel(getattr(logging, log_level))
    
    # Console handler with JSON formatting
    console_handler = logging.StreamHandler(sys.stdout)
    formatter = CustomJsonFormatter(
        '%(timestamp)s %(level)s %(name)s %(message)s'
    )
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler for error logs
    error_handler = logging.handlers.RotatingFileHandler(
        '/var/log/promptsentinel/error.log',
        maxBytes=10485760,  # 10MB
        backupCount=5
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(formatter)
    logger.addHandler(error_handler)
    
    # Audit log for security events
    audit_handler = logging.handlers.RotatingFileHandler(
        '/var/log/promptsentinel/audit.log',
        maxBytes=10485760,
        backupCount=10
    )
    audit_handler.setFormatter(formatter)
    audit_logger = logging.getLogger('promptsentinel.audit')
    audit_logger.addHandler(audit_handler)
    
    return logger

# Usage
logger = setup_logging(os.getenv('LOG_LEVEL', 'INFO'))

# Log with context
logger.info("Detection performed", extra={
    "verdict": "block",
    "confidence": 0.95,
    "threat_category": "prompt_injection",
    "user_id": "user123",
    "trace_id": "abc-123-def"
})

# Audit logging
audit_logger = logging.getLogger('promptsentinel.audit')
audit_logger.info("Security event", extra={
    "event_type": "threat_blocked",
    "user": "user123",
    "ip_address": "192.168.1.1",
    "threat": "sql_injection_attempt"
})
```

### Log Aggregation with ELK Stack

```yaml
# docker-compose.logging.yml
version: '3.8'

services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.11.0
    environment:
      - discovery.type=single-node
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
      - xpack.security.enabled=false
    volumes:
      - elasticsearch-data:/usr/share/elasticsearch/data
    ports:
      - "9200:9200"
      
  logstash:
    image: docker.elastic.co/logstash/logstash:8.11.0
    volumes:
      - ./logstash.conf:/usr/share/logstash/pipeline/logstash.conf
    ports:
      - "5000:5000"
    depends_on:
      - elasticsearch
      
  kibana:
    image: docker.elastic.co/kibana/kibana:8.11.0
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
    ports:
      - "5601:5601"
    depends_on:
      - elasticsearch
      
  filebeat:
    image: docker.elastic.co/beats/filebeat:8.11.0
    volumes:
      - ./filebeat.yml:/usr/share/filebeat/filebeat.yml
      - /var/log/promptsentinel:/var/log/promptsentinel:ro
    depends_on:
      - logstash

volumes:
  elasticsearch-data:
```

### Logstash Configuration

```ruby
# logstash.conf
input {
  beats {
    port => 5044
  }
  
  tcp {
    port => 5000
    codec => json
  }
}

filter {
  if [service] == "promptsentinel" {
    # Parse JSON logs
    json {
      source => "message"
    }
    
    # Add GeoIP for IP addresses
    if [ip_address] {
      geoip {
        source => "ip_address"
        target => "geoip"
      }
    }
    
    # Parse user agent if present
    if [user_agent] {
      useragent {
        source => "user_agent"
        target => "ua"
      }
    }
    
    # Add threat severity
    if [threat_category] {
      mutate {
        add_field => {
          "threat_severity" => "high"
        }
      }
      
      if [threat_category] in ["pii_exposure", "data_leak"] {
        mutate {
          update => { "threat_severity" => "critical" }
        }
      }
    }
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "promptsentinel-%{+YYYY.MM.dd}"
  }
  
  # Alert on critical threats
  if [threat_severity] == "critical" {
    email {
      to => "security@example.com"
      subject => "Critical Security Threat Detected"
      body => "Threat: %{threat_category}\nUser: %{user_id}\nTime: %{timestamp}"
    }
  }
}
```

## Distributed Tracing

### OpenTelemetry Setup

```python
# src/prompt_sentinel/tracing/setup.py
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.resources import Resource
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.requests import RequestsInstrumentor
from opentelemetry.instrumentation.redis import RedisInstrumentor

def setup_tracing(app):
    """Configure OpenTelemetry tracing."""
    
    # Create resource
    resource = Resource.create({
        "service.name": "promptsentinel",
        "service.version": "1.0.0",
        "environment": os.getenv("ENVIRONMENT", "development")
    })
    
    # Create tracer provider
    provider = TracerProvider(resource=resource)
    
    # Configure OTLP exporter
    otlp_exporter = OTLPSpanExporter(
        endpoint=os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317"),
        insecure=True
    )
    
    # Add span processor
    span_processor = BatchSpanProcessor(otlp_exporter)
    provider.add_span_processor(span_processor)
    
    # Set global tracer provider
    trace.set_tracer_provider(provider)
    
    # Instrument libraries
    FastAPIInstrumentor.instrument_app(app)
    RequestsInstrumentor().instrument()
    RedisInstrumentor().instrument()
    
    return trace.get_tracer("promptsentinel")

# Usage in application
tracer = setup_tracing(app)

@app.post("/api/v1/detect")
async def detect(request: DetectionRequest):
    with tracer.start_as_current_span("detection") as span:
        span.set_attribute("detection.mode", request.detection_mode)
        span.set_attribute("prompt.length", len(request.prompt))
        
        # Heuristic detection span
        with tracer.start_as_current_span("heuristic_detection"):
            heuristic_result = perform_heuristic_detection(request.prompt)
            span.set_attribute("heuristic.verdict", heuristic_result.verdict)
        
        # LLM classification span
        with tracer.start_as_current_span("llm_classification"):
            llm_result = perform_llm_classification(request.prompt)
            span.set_attribute("llm.verdict", llm_result.verdict)
            span.set_attribute("llm.provider", llm_result.provider)
        
        # Combine results
        final_verdict = combine_verdicts(heuristic_result, llm_result)
        span.set_attribute("final.verdict", final_verdict)
        
        return {"verdict": final_verdict}
```

### Jaeger Configuration

```yaml
# docker-compose.tracing.yml
version: '3.8'

services:
  jaeger:
    image: jaegertracing/all-in-one:latest
    environment:
      - COLLECTOR_OTLP_ENABLED=true
    ports:
      - "16686:16686"  # Jaeger UI
      - "4317:4317"    # OTLP gRPC
      - "4318:4318"    # OTLP HTTP
      - "14268:14268"  # Jaeger collector
    
  otel-collector:
    image: otel/opentelemetry-collector-contrib:latest
    volumes:
      - ./otel-collector-config.yaml:/etc/otel-collector-config.yaml
    command: ["--config=/etc/otel-collector-config.yaml"]
    ports:
      - "4319:4317"  # OTLP gRPC
      - "8888:8888"  # Prometheus metrics
    depends_on:
      - jaeger
```

## Alerting Rules

### Prometheus Alert Rules

```yaml
# alerts/promptsentinel.yml
groups:
  - name: promptsentinel
    interval: 30s
    rules:
      # High error rate
      - alert: HighErrorRate
        expr: |
          (
            rate(promptsentinel_errors_total[5m]) /
            rate(promptsentinel_requests_total[5m])
          ) > 0.05
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High error rate detected"
          description: "Error rate is {{ $value | humanizePercentage }} for the last 5 minutes"
      
      # High latency
      - alert: HighLatency
        expr: |
          histogram_quantile(0.95,
            rate(promptsentinel_request_duration_seconds_bucket[5m])
          ) > 1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High latency detected"
          description: "P95 latency is {{ $value }}s"
      
      # Low cache hit rate
      - alert: LowCacheHitRate
        expr: |
          (
            rate(promptsentinel_cache_hits_total[5m]) /
            (rate(promptsentinel_cache_hits_total[5m]) + rate(promptsentinel_cache_misses_total[5m]))
          ) < 0.5
        for: 10m
        labels:
          severity: info
        annotations:
          summary: "Cache hit rate below 50%"
          description: "Cache hit rate is {{ $value | humanizePercentage }}"
      
      # High threat rate
      - alert: HighThreatRate
        expr: rate(promptsentinel_threats_blocked_total[5m]) > 1
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "High rate of security threats"
          description: "Blocking {{ $value }} threats per second"
      
      # LLM provider failures
      - alert: LLMProviderDown
        expr: rate(promptsentinel_llm_errors_total[5m]) > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "LLM provider experiencing errors"
          description: "{{ $labels.provider }} error rate: {{ $value }}/s"
      
      # Budget alert
      - alert: BudgetThresholdReached
        expr: promptsentinel_budget_usage_percent > 80
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: "API budget usage above 80%"
          description: "Current usage: {{ $value }}%"
      
      # Service down
      - alert: ServiceDown
        expr: up{job="promptsentinel"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "PromptSentinel service is down"
          description: "Service has been down for more than 1 minute"
```

### AlertManager Configuration

```yaml
# alertmanager.yml
global:
  resolve_timeout: 5m
  slack_api_url: 'YOUR_SLACK_WEBHOOK_URL'

route:
  group_by: ['alertname', 'cluster', 'service']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 12h
  receiver: 'default'
  
  routes:
    - match:
        severity: critical
      receiver: 'pagerduty'
      continue: true
      
    - match:
        severity: warning
      receiver: 'slack'
      
    - match:
        alertname: BudgetThresholdReached
      receiver: 'email'

receivers:
  - name: 'default'
    slack_configs:
      - channel: '#alerts'
        title: 'PromptSentinel Alert'
        text: '{{ range .Alerts }}{{ .Annotations.summary }}{{ end }}'
        
  - name: 'pagerduty'
    pagerduty_configs:
      - service_key: 'YOUR_PAGERDUTY_KEY'
        description: '{{ .GroupLabels.alertname }}'
        
  - name: 'email'
    email_configs:
      - to: 'ops@example.com'
        from: 'alertmanager@example.com'
        smarthost: 'smtp.example.com:587'
        auth_username: 'alertmanager@example.com'
        auth_password: 'password'
        headers:
          Subject: 'PromptSentinel Alert: {{ .GroupLabels.alertname }}'
```

## Health Checks

### Health Check Implementation

```python
# src/prompt_sentinel/health/checks.py
from typing import Dict, Any
import asyncio
import aioredis
import httpx
from datetime import datetime

class HealthChecker:
    def __init__(self, config):
        self.config = config
        self.checks = {
            "database": self.check_database,
            "redis": self.check_redis,
            "llm_providers": self.check_llm_providers,
            "disk_space": self.check_disk_space,
            "memory": self.check_memory
        }
    
    async def check_health(self) -> Dict[str, Any]:
        """Perform comprehensive health check."""
        start_time = datetime.utcnow()
        
        # Run all checks concurrently
        results = await asyncio.gather(
            *[check() for check in self.checks.values()],
            return_exceptions=True
        )
        
        # Compile results
        health_status = {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "duration_ms": (datetime.utcnow() - start_time).total_seconds() * 1000,
            "checks": {}
        }
        
        for (name, check), result in zip(self.checks.items(), results):
            if isinstance(result, Exception):
                health_status["checks"][name] = {
                    "status": "unhealthy",
                    "error": str(result)
                }
                health_status["status"] = "degraded"
            else:
                health_status["checks"][name] = result
                if result.get("status") != "healthy":
                    health_status["status"] = "degraded"
        
        return health_status
    
    async def check_redis(self) -> Dict[str, Any]:
        """Check Redis connectivity."""
        try:
            redis = await aioredis.from_url(self.config.redis_url)
            await redis.ping()
            info = await redis.info()
            await redis.close()
            
            return {
                "status": "healthy",
                "connected": True,
                "version": info.get("redis_version"),
                "used_memory": info.get("used_memory_human")
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "connected": False,
                "error": str(e)
            }
    
    async def check_llm_providers(self) -> Dict[str, Any]:
        """Check LLM provider availability."""
        providers_status = {}
        
        for provider in ["anthropic", "openai", "gemini"]:
            try:
                # Test provider endpoint
                async with httpx.AsyncClient() as client:
                    if provider == "anthropic":
                        response = await client.get(
                            "https://api.anthropic.com/v1/models",
                            headers={"x-api-key": self.config.anthropic_key}
                        )
                    elif provider == "openai":
                        response = await client.get(
                            "https://api.openai.com/v1/models",
                            headers={"Authorization": f"Bearer {self.config.openai_key}"}
                        )
                    # ... other providers
                    
                providers_status[provider] = {
                    "status": "healthy" if response.status_code == 200 else "degraded",
                    "response_time_ms": response.elapsed.total_seconds() * 1000
                }
            except Exception as e:
                providers_status[provider] = {
                    "status": "unhealthy",
                    "error": str(e)
                }
        
        overall_status = "healthy"
        if all(p["status"] == "unhealthy" for p in providers_status.values()):
            overall_status = "unhealthy"
        elif any(p["status"] != "healthy" for p in providers_status.values()):
            overall_status = "degraded"
        
        return {
            "status": overall_status,
            "providers": providers_status
        }
    
    async def check_disk_space(self) -> Dict[str, Any]:
        """Check available disk space."""
        import shutil
        
        usage = shutil.disk_usage("/")
        percent_used = (usage.used / usage.total) * 100
        
        return {
            "status": "healthy" if percent_used < 80 else "warning",
            "percent_used": percent_used,
            "free_gb": usage.free / (1024**3)
        }
    
    async def check_memory(self) -> Dict[str, Any]:
        """Check memory usage."""
        import psutil
        
        memory = psutil.virtual_memory()
        
        return {
            "status": "healthy" if memory.percent < 80 else "warning",
            "percent_used": memory.percent,
            "available_gb": memory.available / (1024**3)
        }

# Kubernetes probes
@app.get("/health/live")
async def liveness_probe():
    """Kubernetes liveness probe."""
    return {"status": "alive"}

@app.get("/health/ready")
async def readiness_probe():
    """Kubernetes readiness probe."""
    health = await health_checker.check_health()
    
    if health["status"] == "unhealthy":
        raise HTTPException(status_code=503, detail=health)
    
    return health
```

## Performance Monitoring

### APM with New Relic

```python
# newrelic.ini
[newrelic]
license_key = YOUR_LICENSE_KEY
app_name = PromptSentinel
monitor_mode = true
log_level = info
high_security = false
transaction_tracer.enabled = true
transaction_tracer.transaction_threshold = apdex_f
error_collector.enabled = true
browser_monitoring.auto_instrument = true
thread_profiler.enabled = true

# Custom instrumentation
import newrelic.agent

@newrelic.agent.function_trace()
def detect_prompt(prompt):
    # Detection logic
    pass

@newrelic.agent.background_task()
def process_batch(prompts):
    # Batch processing
    pass
```

### Custom Performance Metrics

```python
# src/prompt_sentinel/monitoring/performance.py
import time
from contextlib import contextmanager
from prometheus_client import Summary, Histogram

# Performance metrics
detection_time = Summary(
    'promptsentinel_detection_duration_seconds',
    'Time spent in detection',
    ['strategy']
)

cache_operation_time = Histogram(
    'promptsentinel_cache_operation_duration_seconds',
    'Cache operation duration',
    ['operation'],
    buckets=(0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0)
)

@contextmanager
def measure_time(metric, **labels):
    """Context manager for measuring execution time."""
    start = time.perf_counter()
    try:
        yield
    finally:
        duration = time.perf_counter() - start
        metric.labels(**labels).observe(duration)

# Usage
async def detect(prompt):
    with measure_time(detection_time, strategy="heuristic"):
        heuristic_result = await heuristic_detection(prompt)
    
    with measure_time(detection_time, strategy="llm"):
        llm_result = await llm_classification(prompt)
    
    return combine_results(heuristic_result, llm_result)
```

## Security Monitoring

### Security Event Tracking

```python
# src/prompt_sentinel/monitoring/security.py
from datetime import datetime
import hashlib

class SecurityMonitor:
    def __init__(self, logger, metrics):
        self.logger = logger
        self.metrics = metrics
        self.threat_cache = {}
    
    def log_threat(self, threat_data):
        """Log security threat with context."""
        threat_hash = hashlib.md5(
            f"{threat_data['prompt'][:100]}".encode()
        ).hexdigest()
        
        # Check for repeat attacks
        if threat_hash in self.threat_cache:
            self.threat_cache[threat_hash]["count"] += 1
            
            if self.threat_cache[threat_hash]["count"] > 5:
                self.logger.critical("Repeated attack pattern detected", extra={
                    "threat_hash": threat_hash,
                    "count": self.threat_cache[threat_hash]["count"],
                    "category": threat_data["category"]
                })
        else:
            self.threat_cache[threat_hash] = {
                "count": 1,
                "first_seen": datetime.utcnow(),
                "category": threat_data["category"]
            }
        
        # Log threat
        self.logger.warning("Security threat detected", extra={
            "threat_category": threat_data["category"],
            "confidence": threat_data["confidence"],
            "user_id": threat_data.get("user_id"),
            "ip_address": threat_data.get("ip_address"),
            "threat_hash": threat_hash
        })
        
        # Update metrics
        self.metrics.threats_blocked.labels(
            category=threat_data["category"]
        ).inc()
    
    def analyze_patterns(self):
        """Analyze attack patterns."""
        patterns = {}
        
        for threat_hash, data in self.threat_cache.items():
            category = data["category"]
            if category not in patterns:
                patterns[category] = {"count": 0, "unique": 0}
            
            patterns[category]["count"] += data["count"]
            patterns[category]["unique"] += 1
        
        return patterns
```

## Cost Monitoring

### API Usage Tracking

```python
# src/prompt_sentinel/monitoring/costs.py
class CostMonitor:
    # Pricing per 1M tokens (example)
    PRICING = {
        "anthropic": {
            "claude-3-opus": {"input": 15.0, "output": 75.0},
            "claude-3-sonnet": {"input": 3.0, "output": 15.0}
        },
        "openai": {
            "gpt-4": {"input": 30.0, "output": 60.0},
            "gpt-3.5-turbo": {"input": 0.5, "output": 1.5}
        }
    }
    
    def __init__(self):
        self.usage = {
            "tokens": {},
            "requests": {},
            "costs": {}
        }
    
    def track_usage(self, provider, model, input_tokens, output_tokens):
        """Track API usage and calculate costs."""
        key = f"{provider}:{model}"
        
        # Update token counts
        if key not in self.usage["tokens"]:
            self.usage["tokens"][key] = {"input": 0, "output": 0}
        
        self.usage["tokens"][key]["input"] += input_tokens
        self.usage["tokens"][key]["output"] += output_tokens
        
        # Calculate cost
        pricing = self.PRICING.get(provider, {}).get(model, {})
        if pricing:
            input_cost = (input_tokens / 1_000_000) * pricing["input"]
            output_cost = (output_tokens / 1_000_000) * pricing["output"]
            total_cost = input_cost + output_cost
            
            if key not in self.usage["costs"]:
                self.usage["costs"][key] = 0
            self.usage["costs"][key] += total_cost
            
            # Update metrics
            cost_metric.labels(provider=provider, model=model).inc(total_cost)
        
        return total_cost
    
    def get_daily_cost(self):
        """Calculate daily API costs."""
        return sum(self.usage["costs"].values())
    
    def get_budget_status(self, daily_limit):
        """Check budget status."""
        current_spend = self.get_daily_cost()
        percentage = (current_spend / daily_limit) * 100
        
        return {
            "current_spend": current_spend,
            "limit": daily_limit,
            "percentage": percentage,
            "remaining": daily_limit - current_spend,
            "status": "ok" if percentage < 80 else "warning" if percentage < 100 else "exceeded"
        }
```

## Best Practices

1. **Use structured logging** - JSON format for easy parsing
2. **Implement distributed tracing** - Track requests across services
3. **Set up alerting thresholds** - Based on baseline metrics
4. **Monitor costs continuously** - Prevent budget overruns
5. **Track security metrics** - Identify attack patterns
6. **Use sampling for high-volume** - Reduce monitoring overhead
7. **Archive old data** - Manage storage costs
8. **Test monitoring setup** - Ensure alerts work
9. **Document runbooks** - Clear incident response procedures
10. **Review metrics regularly** - Optimize based on insights

## Additional Resources

- [Prometheus Documentation](https://prometheus.io/docs/)
- [Grafana Documentation](https://grafana.com/docs/)
- [OpenTelemetry Documentation](https://opentelemetry.io/docs/)
- [Deployment Best Practices](./DEPLOYMENT_BEST_PRACTICES.md)
- [Troubleshooting Guide](./TROUBLESHOOTING.md)