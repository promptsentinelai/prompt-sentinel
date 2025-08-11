# Deployment Best Practices

This guide provides comprehensive best practices for deploying PromptSentinel in production environments.

## Table of Contents
- [Architecture Patterns](#architecture-patterns)
- [Deployment Modes](#deployment-modes)
- [Container Deployment](#container-deployment)
- [Kubernetes Deployment](#kubernetes-deployment)
- [Cloud Deployments](#cloud-deployments)
- [Security Configuration](#security-configuration)
- [Performance Tuning](#performance-tuning)
- [Monitoring & Observability](#monitoring--observability)
- [High Availability](#high-availability)
- [Disaster Recovery](#disaster-recovery)

## Architecture Patterns

### Sidecar Pattern

Deploy PromptSentinel as a sidecar container alongside your application:

```yaml
# kubernetes/sidecar-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app-with-sentinel
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: app
        image: your-app:latest
        env:
        - name: PROMPTSENTINEL_URL
          value: "http://localhost:8080"
        
      - name: promptsentinel
        image: promptsentinel/promptsentinel:latest
        ports:
        - containerPort: 8080
        env:
        - name: AUTHENTICATION_MODE
          value: "none"  # Internal communication only
        - name: REDIS_URL
          value: "redis://redis-service:6379"
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "500m"
```

**Advantages:**
- Low latency (localhost communication)
- Network isolation
- Simplified authentication
- Per-pod scaling

**Best for:**
- Microservices architectures
- High-throughput applications
- Network-sensitive deployments

### Centralized Service Pattern

Deploy PromptSentinel as a centralized service:

```yaml
# kubernetes/central-service.yaml
apiVersion: v1
kind: Service
metadata:
  name: promptsentinel-service
spec:
  selector:
    app: promptsentinel
  ports:
  - port: 80
    targetPort: 8080
  type: LoadBalancer

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: promptsentinel-central
spec:
  replicas: 5
  template:
    spec:
      containers:
      - name: promptsentinel
        image: promptsentinel/promptsentinel:latest
        env:
        - name: AUTHENTICATION_MODE
          value: "required"
        - name: API_KEY_HEADER
          value: "X-API-Key"
        resources:
          requests:
            memory: "1Gi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "1000m"
```

**Advantages:**
- Centralized management
- Shared caching
- Easier monitoring
- Cost-effective for multiple services

**Best for:**
- Multi-tenant environments
- Organizations with many applications
- Centralized security teams

### Edge Proxy Pattern

Deploy as an edge security proxy:

```nginx
# nginx.conf
upstream backend {
    server app-service:3000;
}

upstream promptsentinel {
    server promptsentinel-service:8080;
}

server {
    listen 80;
    
    location /api/ {
        # Validate with PromptSentinel first
        set $prompt_body $request_body;
        
        access_by_lua_block {
            local http = require "resty.http"
            local json = require "cjson"
            
            ngx.req.read_body()
            local body = ngx.req.get_body_data()
            
            if body then
                local data = json.decode(body)
                if data.prompt then
                    local httpc = http.new()
                    local res = httpc:request_uri("http://promptsentinel:8080/api/v1/detect", {
                        method = "POST",
                        body = json.encode({prompt = data.prompt}),
                        headers = {
                            ["Content-Type"] = "application/json",
                        }
                    })
                    
                    if res then
                        local result = json.decode(res.body)
                        if result.verdict == "block" then
                            ngx.status = 400
                            ngx.say(json.encode({error = "Security threat detected"}))
                            ngx.exit(ngx.HTTP_BAD_REQUEST)
                        end
                    end
                end
            }
        }
        
        proxy_pass http://backend;
    }
}
```

## Deployment Modes

### Development Mode

```yaml
# docker-compose.dev.yml
version: '3.8'

services:
  promptsentinel:
    image: promptsentinel/promptsentinel:latest
    ports:
      - "8080:8080"
    environment:
      - LOG_LEVEL=DEBUG
      - AUTHENTICATION_MODE=optional
      - DETECTION_MODE=permissive
      - ENABLE_METRICS=true
      - ENABLE_PROFILING=true
    volumes:
      - ./config:/app/config
      - ./logs:/app/logs
```

### Staging Mode

```yaml
# docker-compose.staging.yml
version: '3.8'

services:
  promptsentinel:
    image: promptsentinel/promptsentinel:staging
    ports:
      - "8080:8080"
    environment:
      - LOG_LEVEL=INFO
      - AUTHENTICATION_MODE=required
      - DETECTION_MODE=moderate
      - REDIS_URL=redis://redis:6379
      - METRICS_ENABLED=true
    depends_on:
      - redis
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
```

### Production Mode

```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  promptsentinel:
    image: promptsentinel/promptsentinel:v1.0.0
    deploy:
      replicas: 3
      restart_policy:
        condition: on-failure
        delay: 5s
        max_attempts: 3
      resources:
        limits:
          cpus: '2'
          memory: 2G
        reservations:
          cpus: '1'
          memory: 1G
    environment:
      - LOG_LEVEL=WARNING
      - AUTHENTICATION_MODE=required
      - DETECTION_MODE=strict
      - REDIS_CLUSTER=redis-cluster:6379
      - ENABLE_TLS=true
      - TLS_CERT_PATH=/certs/tls.crt
      - TLS_KEY_PATH=/certs/tls.key
    volumes:
      - /etc/ssl/certs:/certs:ro
    secrets:
      - anthropic_api_key
      - openai_api_key
      - api_keys

secrets:
  anthropic_api_key:
    external: true
  openai_api_key:
    external: true
  api_keys:
    external: true
```

## Container Deployment

### Docker Best Practices

```dockerfile
# Dockerfile.production
FROM python:3.11-slim-bookworm AS builder

# Security: Run as non-root user
RUN groupadd -r promptsentinel && useradd -r -g promptsentinel promptsentinel

# Install dependencies
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY --chown=promptsentinel:promptsentinel . .

# Production image
FROM python:3.11-slim-bookworm

# Install runtime dependencies only
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /app /app

# Security hardening
RUN groupadd -r promptsentinel && useradd -r -g promptsentinel promptsentinel
USER promptsentinel

WORKDIR /app

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

EXPOSE 8080

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
```

### Container Security Scanning

```bash
# Scan for vulnerabilities
docker scan promptsentinel/promptsentinel:latest

# Use Trivy for comprehensive scanning
trivy image promptsentinel/promptsentinel:latest

# Snyk container scanning
snyk container test promptsentinel/promptsentinel:latest
```

## Kubernetes Deployment

### Production-Ready Kubernetes Manifest

```yaml
# kubernetes/production-deployment.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: promptsentinel

---
apiVersion: v1
kind: ConfigMap
metadata:
  name: promptsentinel-config
  namespace: promptsentinel
data:
  config.yaml: |
    server:
      port: 8080
      timeout: 30s
    detection:
      mode: strict
      cache_ttl: 3600
    monitoring:
      enabled: true
      port: 9090

---
apiVersion: v1
kind: Secret
metadata:
  name: promptsentinel-secrets
  namespace: promptsentinel
type: Opaque
data:
  anthropic-api-key: <base64-encoded-key>
  openai-api-key: <base64-encoded-key>

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: promptsentinel
  namespace: promptsentinel
  labels:
    app: promptsentinel
spec:
  replicas: 3
  selector:
    matchLabels:
      app: promptsentinel
  template:
    metadata:
      labels:
        app: promptsentinel
    spec:
      serviceAccountName: promptsentinel
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
      - name: promptsentinel
        image: promptsentinel/promptsentinel:v1.0.0
        imagePullPolicy: IfNotPresent
        ports:
        - containerPort: 8080
          name: http
        - containerPort: 9090
          name: metrics
        env:
        - name: ANTHROPIC_API_KEY
          valueFrom:
            secretKeyRef:
              name: promptsentinel-secrets
              key: anthropic-api-key
        - name: OPENAI_API_KEY
          valueFrom:
            secretKeyRef:
              name: promptsentinel-secrets
              key: openai-api-key
        - name: REDIS_URL
          value: "redis://redis-service:6379"
        volumeMounts:
        - name: config
          mountPath: /app/config
          readOnly: true
        resources:
          requests:
            memory: "1Gi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "1000m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: config
        configMap:
          name: promptsentinel-config

---
apiVersion: v1
kind: Service
metadata:
  name: promptsentinel-service
  namespace: promptsentinel
spec:
  selector:
    app: promptsentinel
  ports:
  - name: http
    port: 80
    targetPort: 8080
  - name: metrics
    port: 9090
    targetPort: 9090
  type: ClusterIP

---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: promptsentinel-hpa
  namespace: promptsentinel
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: promptsentinel
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

### Helm Chart

```yaml
# helm/values.yaml
replicaCount: 3

image:
  repository: promptsentinel/promptsentinel
  tag: v1.0.0
  pullPolicy: IfNotPresent

service:
  type: ClusterIP
  port: 80

ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/rate-limit: "100"
  hosts:
    - host: sentinel.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: sentinel-tls
      hosts:
        - sentinel.example.com

resources:
  limits:
    cpu: 1000m
    memory: 2Gi
  requests:
    cpu: 500m
    memory: 1Gi

autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70

redis:
  enabled: true
  architecture: replication
  auth:
    enabled: true
    password: changeme

monitoring:
  enabled: true
  serviceMonitor:
    enabled: true
```

## Cloud Deployments

### AWS ECS Deployment

```json
{
  "family": "promptsentinel-task",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "1024",
  "memory": "2048",
  "containerDefinitions": [
    {
      "name": "promptsentinel",
      "image": "promptsentinel/promptsentinel:latest",
      "portMappings": [
        {
          "containerPort": 8080,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {
          "name": "REDIS_URL",
          "value": "redis://redis.cache.amazonaws.com:6379"
        }
      ],
      "secrets": [
        {
          "name": "ANTHROPIC_API_KEY",
          "valueFrom": "arn:aws:secretsmanager:region:account:secret:anthropic-key"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/promptsentinel",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      },
      "healthCheck": {
        "command": ["CMD-SHELL", "curl -f http://localhost:8080/health || exit 1"],
        "interval": 30,
        "timeout": 3,
        "retries": 3
      }
    }
  ]
}
```

### Google Cloud Run

```yaml
# cloudrun-service.yaml
apiVersion: serving.knative.dev/v1
kind: Service
metadata:
  name: promptsentinel
  annotations:
    run.googleapis.com/ingress: all
spec:
  template:
    metadata:
      annotations:
        autoscaling.knative.dev/minScale: "1"
        autoscaling.knative.dev/maxScale: "10"
    spec:
      containerConcurrency: 100
      timeoutSeconds: 30
      containers:
      - image: gcr.io/project-id/promptsentinel:latest
        ports:
        - containerPort: 8080
        env:
        - name: REDIS_URL
          value: "redis://10.0.0.3:6379"
        resources:
          limits:
            cpu: "2"
            memory: "2Gi"
```

### Azure Container Instances

```json
{
  "location": "eastus",
  "name": "promptsentinel",
  "properties": {
    "containers": [
      {
        "name": "promptsentinel",
        "properties": {
          "image": "promptsentinel/promptsentinel:latest",
          "ports": [
            {
              "port": 8080,
              "protocol": "TCP"
            }
          ],
          "environmentVariables": [
            {
              "name": "REDIS_URL",
              "value": "redis://cache.redis.cache.windows.net:6379"
            }
          ],
          "resources": {
            "requests": {
              "cpu": 1.0,
              "memoryInGB": 2.0
            }
          }
        }
      }
    ],
    "osType": "Linux",
    "restartPolicy": "Always",
    "ipAddress": {
      "type": "Public",
      "ports": [
        {
          "port": 8080,
          "protocol": "TCP"
        }
      ]
    }
  }
}
```

## Security Configuration

### Environment Variables

```bash
# .env.production
# API Keys (use secrets management in production)
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...
GEMINI_API_KEY=...

# Security Settings
AUTHENTICATION_MODE=required
API_KEY_HEADER=X-API-Key
ALLOWED_ORIGINS=https://app.example.com,https://api.example.com
RATE_LIMIT_ENABLED=true
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=60

# TLS Configuration
ENABLE_TLS=true
TLS_CERT_PATH=/certs/server.crt
TLS_KEY_PATH=/certs/server.key
TLS_MIN_VERSION=1.2

# Detection Settings
DETECTION_MODE=strict
ENABLE_PII_DETECTION=true
MAX_PROMPT_LENGTH=10000
BLOCK_ENCODED_INPUTS=true

# Monitoring
ENABLE_METRICS=true
METRICS_PORT=9090
ENABLE_TRACING=true
JAEGER_ENDPOINT=http://jaeger:14268/api/traces
```

### Network Security

```yaml
# kubernetes/network-policy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: promptsentinel-network-policy
spec:
  podSelector:
    matchLabels:
      app: promptsentinel
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: allowed-app
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: redis
    ports:
    - protocol: TCP
      port: 6379
  - to:
    - namespaceSelector: {}
    ports:
    - protocol: TCP
      port: 443  # For LLM API calls
```

## Performance Tuning

### Redis Configuration

```redis
# redis.conf
maxmemory 2gb
maxmemory-policy allkeys-lru
save ""  # Disable persistence for cache-only
tcp-keepalive 60
timeout 300

# Connection pool
tcp-backlog 511
maxclients 10000

# Performance
rdbcompression no
rdbchecksum no
```

### Application Tuning

```yaml
# config/performance.yaml
server:
  workers: 4  # Number of worker processes
  worker_connections: 1000
  keepalive_timeout: 65
  
connection_pool:
  size: 20
  max_overflow: 10
  timeout: 30
  
cache:
  enabled: true
  ttl: 3600
  max_size: 10000
  
llm_providers:
  timeout: 30
  max_retries: 3
  backoff_factor: 2
  
rate_limiting:
  enabled: true
  requests_per_minute: 100
  burst: 20
```

## Monitoring & Observability

### Prometheus Metrics

```yaml
# prometheus/scrape-config.yaml
scrape_configs:
  - job_name: 'promptsentinel'
    static_configs:
    - targets: ['promptsentinel:9090']
    metrics_path: '/metrics'
    scrape_interval: 30s
```

### Grafana Dashboard

```json
{
  "dashboard": {
    "title": "PromptSentinel Monitoring",
    "panels": [
      {
        "title": "Request Rate",
        "targets": [
          {
            "expr": "rate(promptsentinel_requests_total[5m])"
          }
        ]
      },
      {
        "title": "Detection Verdicts",
        "targets": [
          {
            "expr": "sum by (verdict) (rate(promptsentinel_detections_total[5m]))"
          }
        ]
      },
      {
        "title": "API Latency",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(promptsentinel_request_duration_seconds_bucket[5m]))"
          }
        ]
      },
      {
        "title": "Cache Hit Rate",
        "targets": [
          {
            "expr": "rate(promptsentinel_cache_hits_total[5m]) / rate(promptsentinel_cache_requests_total[5m])"
          }
        ]
      }
    ]
  }
}
```

### Logging Configuration

```yaml
# logging.yaml
version: 1
formatters:
  default:
    format: '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
  json:
    class: pythonjsonlogger.jsonlogger.JsonFormatter
    
handlers:
  console:
    class: logging.StreamHandler
    level: INFO
    formatter: json
    stream: ext://sys.stdout
    
  file:
    class: logging.handlers.RotatingFileHandler
    level: WARNING
    formatter: json
    filename: /var/log/promptsentinel/app.log
    maxBytes: 10485760  # 10MB
    backupCount: 5
    
loggers:
  promptsentinel:
    level: INFO
    handlers: [console, file]
    propagate: false
```

## High Availability

### Multi-Region Deployment

```yaml
# terraform/multi-region.tf
resource "aws_ecs_service" "promptsentinel_us_east" {
  name            = "promptsentinel-us-east"
  cluster         = aws_ecs_cluster.us_east.id
  task_definition = aws_ecs_task_definition.promptsentinel.arn
  desired_count   = 3
  
  load_balancer {
    target_group_arn = aws_lb_target_group.us_east.arn
    container_name   = "promptsentinel"
    container_port   = 8080
  }
}

resource "aws_ecs_service" "promptsentinel_eu_west" {
  name            = "promptsentinel-eu-west"
  cluster         = aws_ecs_cluster.eu_west.id
  task_definition = aws_ecs_task_definition.promptsentinel.arn
  desired_count   = 3
  
  provider = aws.eu_west
  
  load_balancer {
    target_group_arn = aws_lb_target_group.eu_west.arn
    container_name   = "promptsentinel"
    container_port   = 8080
  }
}

# Route53 for geo-routing
resource "aws_route53_record" "promptsentinel" {
  zone_id = aws_route53_zone.main.zone_id
  name    = "api.promptsentinel.com"
  type    = "A"
  
  set_identifier = "us-east"
  geolocation_routing_policy {
    continent = "NA"
  }
  
  alias {
    name                   = aws_lb.us_east.dns_name
    zone_id                = aws_lb.us_east.zone_id
    evaluate_target_health = true
  }
}
```

### Database Replication

```yaml
# redis-cluster.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: redis-cluster-config
data:
  redis.conf: |
    cluster-enabled yes
    cluster-config-file nodes.conf
    cluster-node-timeout 5000
    appendonly yes
    
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: redis-cluster
spec:
  serviceName: redis-cluster
  replicas: 6
  template:
    spec:
      containers:
      - name: redis
        image: redis:7-alpine
        command: ["redis-server", "/conf/redis.conf"]
        volumeMounts:
        - name: conf
          mountPath: /conf
        - name: data
          mountPath: /data
  volumeClaimTemplates:
  - metadata:
      name: data
    spec:
      accessModes: ["ReadWriteOnce"]
      resources:
        requests:
          storage: 10Gi
```

## Disaster Recovery

### Backup Strategy

```bash
#!/bin/bash
# backup.sh

# Backup Redis data
redis-cli --rdb /backup/redis-$(date +%Y%m%d).rdb

# Backup configuration
tar -czf /backup/config-$(date +%Y%m%d).tar.gz /app/config

# Upload to S3
aws s3 cp /backup/ s3://promptsentinel-backups/ --recursive

# Clean old backups (keep 30 days)
find /backup -type f -mtime +30 -delete
```

### Recovery Procedures

```bash
#!/bin/bash
# restore.sh

# Restore from specific date
RESTORE_DATE=$1

# Download backups
aws s3 cp s3://promptsentinel-backups/redis-${RESTORE_DATE}.rdb /tmp/
aws s3 cp s3://promptsentinel-backups/config-${RESTORE_DATE}.tar.gz /tmp/

# Stop services
kubectl scale deployment promptsentinel --replicas=0

# Restore Redis
redis-cli --rdb /tmp/redis-${RESTORE_DATE}.rdb
redis-cli FLUSHALL
redis-cli --pipe < /tmp/redis-${RESTORE_DATE}.rdb

# Restore configuration
tar -xzf /tmp/config-${RESTORE_DATE}.tar.gz -C /

# Restart services
kubectl scale deployment promptsentinel --replicas=3

# Verify
kubectl exec -it promptsentinel-0 -- curl http://localhost:8080/health
```

## Deployment Checklist

### Pre-Deployment

- [ ] Security scan container images
- [ ] Review and update dependencies
- [ ] Configure environment variables
- [ ] Set up secrets management
- [ ] Configure monitoring and alerting
- [ ] Set up backup procedures
- [ ] Review network policies
- [ ] Configure rate limiting
- [ ] Set up TLS certificates
- [ ] Review resource limits

### During Deployment

- [ ] Deploy to staging first
- [ ] Run smoke tests
- [ ] Monitor metrics during rollout
- [ ] Use rolling updates
- [ ] Maintain minimum replicas
- [ ] Check health endpoints
- [ ] Verify cache connectivity
- [ ] Test failover scenarios

### Post-Deployment

- [ ] Verify all health checks passing
- [ ] Check monitoring dashboards
- [ ] Verify logging pipeline
- [ ] Test API endpoints
- [ ] Check rate limiting
- [ ] Verify cache hit rates
- [ ] Monitor error rates
- [ ] Document deployment
- [ ] Update runbooks
- [ ] Schedule post-mortem if issues

## Best Practices Summary

1. **Always use health checks** - Configure liveness and readiness probes
2. **Implement rate limiting** - Protect against abuse and DoS
3. **Use connection pooling** - Optimize resource usage
4. **Enable caching** - Reduce latency and API costs
5. **Monitor everything** - Metrics, logs, and traces
6. **Secure secrets** - Never hardcode, use secret management
7. **Plan for failure** - Implement circuit breakers and retries
8. **Scale horizontally** - Use replicas and load balancing
9. **Regular backups** - Automate backup and restoration
10. **Document everything** - Maintain runbooks and procedures

## Additional Resources

- [API Documentation](./API_EXAMPLES.md)
- [Integration Guides](./integrations/)
- [Security Best Practices](../README.md#security-best-practices)
- [Monitoring Guide](./MONITORING.md)
- [Troubleshooting Guide](./TROUBLESHOOTING.md)