# 🚀 PromptSentinel Deployment Guide

## Overview

This guide covers various deployment options for PromptSentinel, from simple Docker containers to production Kubernetes clusters.

## 📦 Docker Hub

PromptSentinel is available on Docker Hub:

```bash
docker pull promptsentinel/prompt-sentinel:latest
```

Available tags:
- `latest` - Latest stable release
- `v1.0.0`, `v1.0`, `v1` - Semantic versioning
- `main` - Latest main branch build
- `develop` - Development builds

## 🐳 Docker Deployment

### Quick Start

```bash
# Pull the image
docker pull promptsentinel/prompt-sentinel:latest

# Run with environment file
docker run -d \
  --name prompt-sentinel \
  -p 8080:8080 \
  --env-file .env \
  --restart unless-stopped \
  promptsentinel/prompt-sentinel:latest
```

### Docker Compose

#### Basic Setup

```yaml
# docker-compose.yml
version: '3.8'

services:
  prompt-sentinel:
    image: promptsentinel/prompt-sentinel:latest
    ports:
      - "8080:8080"
    env_file:
      - .env
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
```

#### With Redis Cache

```yaml
# docker-compose.yml
version: '3.8'

services:
  prompt-sentinel:
    image: promptsentinel/prompt-sentinel:latest
    ports:
      - "8080:8080"
    env_file:
      - .env
    environment:
      - REDIS_ENABLED=true
      - REDIS_HOST=redis
      - REDIS_PORT=6379
      - REDIS_PASSWORD=${REDIS_PASSWORD}
    depends_on:
      - redis
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    command: >
      redis-server
      --requirepass ${REDIS_PASSWORD}
      --save ""
      --appendonly no
      --maxmemory 256mb
      --maxmemory-policy allkeys-lru
    volumes:
      - redis-data:/data
    restart: unless-stopped

volumes:
  redis-data:
```

### Environment Configuration

Create a `.env` file with your configuration:

```bash
# Required: At least one LLM provider
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...
GEMINI_API_KEY=AIza...

# Optional: Redis cache
REDIS_ENABLED=true
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_PASSWORD=your-secure-password

# Optional: Detection settings
DETECTION_MODE=moderate
CONFIDENCE_THRESHOLD=0.7
PII_DETECTION_ENABLED=true

# Optional: API settings
API_HOST=0.0.0.0
API_PORT=8080
LOG_LEVEL=INFO
```

## ☸️ Kubernetes Deployment

### Helm Chart

```bash
# Add the PromptSentinel Helm repository
helm repo add promptsentinel https://charts.promptsentinel.ai
helm repo update

# Install with custom values
helm install prompt-sentinel promptsentinel/prompt-sentinel \
  --set image.tag=latest \
  --set secrets.anthropicApiKey=$ANTHROPIC_API_KEY \
  --set redis.enabled=true \
  --set ingress.enabled=true \
  --set ingress.hosts[0].host=api.example.com
```

### Manual Kubernetes Deployment

#### 1. Create Namespace

```yaml
# namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: prompt-sentinel
```

#### 2. Create Secrets

```bash
kubectl create secret generic prompt-sentinel-secrets \
  --from-literal=anthropic-api-key=$ANTHROPIC_API_KEY \
  --from-literal=openai-api-key=$OPENAI_API_KEY \
  --from-literal=redis-password=$(openssl rand -base64 32) \
  -n prompt-sentinel
```

#### 3. Deploy Application

```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: prompt-sentinel
  namespace: prompt-sentinel
spec:
  replicas: 3
  selector:
    matchLabels:
      app: prompt-sentinel
  template:
    metadata:
      labels:
        app: prompt-sentinel
    spec:
      containers:
      - name: prompt-sentinel
        image: promptsentinel/prompt-sentinel:latest
        ports:
        - containerPort: 8080
        env:
        - name: ANTHROPIC_API_KEY
          valueFrom:
            secretKeyRef:
              name: prompt-sentinel-secrets
              key: anthropic-api-key
        - name: REDIS_ENABLED
          value: "true"
        - name: REDIS_HOST
          value: "redis-service"
        resources:
          requests:
            memory: "256Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 10
```

#### 4. Create Service

```yaml
# service.yaml
apiVersion: v1
kind: Service
metadata:
  name: prompt-sentinel-service
  namespace: prompt-sentinel
spec:
  selector:
    app: prompt-sentinel
  ports:
  - port: 80
    targetPort: 8080
  type: LoadBalancer
```

#### 5. Configure Ingress

```yaml
# ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: prompt-sentinel-ingress
  namespace: prompt-sentinel
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/rate-limit: "100"
spec:
  tls:
  - hosts:
    - api.promptsentinel.example.com
    secretName: prompt-sentinel-tls
  rules:
  - host: api.promptsentinel.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: prompt-sentinel-service
            port:
              number: 80
```

## ☁️ Cloud Platform Deployments

### AWS ECS

#### Task Definition

```json
{
  "family": "prompt-sentinel",
  "taskRoleArn": "arn:aws:iam::ACCOUNT:role/ecsTaskRole",
  "executionRoleArn": "arn:aws:iam::ACCOUNT:role/ecsExecutionRole",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "containerDefinitions": [
    {
      "name": "prompt-sentinel",
      "image": "promptsentinel/prompt-sentinel:latest",
      "portMappings": [
        {
          "containerPort": 8080,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {"name": "REDIS_ENABLED", "value": "true"},
        {"name": "REDIS_HOST", "value": "redis.cache.amazonaws.com"}
      ],
      "secrets": [
        {
          "name": "ANTHROPIC_API_KEY",
          "valueFrom": "arn:aws:secretsmanager:region:ACCOUNT:secret:anthropic-key"
        }
      ],
      "healthCheck": {
        "command": ["CMD-SHELL", "curl -f http://localhost:8080/health || exit 1"],
        "interval": 30,
        "timeout": 5,
        "retries": 3
      },
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/prompt-sentinel",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
}
```

### Google Cloud Run

```bash
# Build and push to Google Container Registry
gcloud builds submit --tag gcr.io/PROJECT-ID/prompt-sentinel

# Deploy to Cloud Run
gcloud run deploy prompt-sentinel \
  --image gcr.io/PROJECT-ID/prompt-sentinel \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars="REDIS_ENABLED=true,REDIS_HOST=10.0.0.1" \
  --set-secrets="ANTHROPIC_API_KEY=anthropic-key:latest" \
  --memory 512Mi \
  --cpu 1 \
  --min-instances 1 \
  --max-instances 10
```

### Azure Container Instances

```bash
# Create resource group
az group create --name prompt-sentinel-rg --location eastus

# Create container instance
az container create \
  --resource-group prompt-sentinel-rg \
  --name prompt-sentinel \
  --image promptsentinel/prompt-sentinel:latest \
  --dns-name-label prompt-sentinel-api \
  --ports 8080 \
  --environment-variables \
    REDIS_ENABLED=true \
    REDIS_HOST=prompt-sentinel.redis.cache.windows.net \
  --secure-environment-variables \
    ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  --cpu 1 \
  --memory 1
```

## 🔧 Production Configuration

### High Availability Setup

```yaml
# production-ha.yaml
version: '3.8'

services:
  prompt-sentinel-1:
    image: promptsentinel/prompt-sentinel:latest
    environment:
      - NODE_ID=1
    deploy:
      replicas: 2
      placement:
        constraints:
          - node.labels.zone == zone-1

  prompt-sentinel-2:
    image: promptsentinel/prompt-sentinel:latest
    environment:
      - NODE_ID=2
    deploy:
      replicas: 2
      placement:
        constraints:
          - node.labels.zone == zone-2

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./certs:/etc/nginx/certs:ro
    depends_on:
      - prompt-sentinel-1
      - prompt-sentinel-2
```

### Nginx Load Balancer Configuration

```nginx
# nginx.conf
upstream prompt_sentinel {
    least_conn;
    server prompt-sentinel-1:8080 max_fails=3 fail_timeout=30s;
    server prompt-sentinel-2:8080 max_fails=3 fail_timeout=30s;
}

server {
    listen 443 ssl http2;
    server_name api.promptsentinel.com;

    ssl_certificate /etc/nginx/certs/cert.pem;
    ssl_certificate_key /etc/nginx/certs/key.pem;

    location / {
        proxy_pass http://prompt_sentinel;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Timeouts
        proxy_connect_timeout 10s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;
        
        # Rate limiting
        limit_req zone=api burst=20 nodelay;
    }
    
    location /health {
        proxy_pass http://prompt_sentinel/health;
        access_log off;
    }
}
```

## 📊 Monitoring Setup

### Prometheus Configuration

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'prompt-sentinel'
    static_configs:
      - targets: ['prompt-sentinel:8080']
    metrics_path: '/metrics'
    scrape_interval: 30s
```

### Grafana Dashboard

Import dashboard ID: `PS-001` from Grafana.com or use our template:

```bash
curl -O https://raw.githubusercontent.com/rhoska/prompt-sentinel/main/deployment/grafana-dashboard.json
```

## 🔒 Security Best Practices

### 1. Use Secrets Management

Never hardcode API keys. Use:
- Kubernetes Secrets
- AWS Secrets Manager
- Google Secret Manager
- Azure Key Vault
- HashiCorp Vault

### 2. Network Security

```yaml
# network-policy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: prompt-sentinel-network-policy
spec:
  podSelector:
    matchLabels:
      app: prompt-sentinel
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: nginx
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: redis
  - to:
    - namespaceSelector: {}
    ports:
    - protocol: TCP
      port: 443  # For LLM APIs
```

### 3. Resource Limits

Always set resource limits to prevent resource exhaustion:

```yaml
resources:
  requests:
    memory: "256Mi"
    cpu: "100m"
  limits:
    memory: "512Mi"
    cpu: "500m"
```

### 4. Health Checks

Configure proper health checks for automatic recovery:

```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 8080
  initialDelaySeconds: 30
  periodSeconds: 30
  timeoutSeconds: 10
  failureThreshold: 3

readinessProbe:
  httpGet:
    path: /health
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 10
  timeoutSeconds: 5
  failureThreshold: 2
```

## 🚨 Troubleshooting

### Common Issues

#### 1. Container fails to start

Check logs:
```bash
docker logs prompt-sentinel
kubectl logs -n prompt-sentinel deployment/prompt-sentinel
```

Common causes:
- Missing API keys
- Invalid environment variables
- Port already in use

#### 2. High memory usage

- Enable Redis caching
- Reduce worker count
- Increase memory limits

#### 3. Slow response times

- Check LLM provider status
- Verify Redis connectivity
- Review rate limiting settings

#### 4. Connection refused

- Verify port mappings
- Check firewall rules
- Confirm service is running

### Debug Mode

Enable debug logging:

```yaml
environment:
  - LOG_LEVEL=DEBUG
  - DEBUG=true
```

## 📝 Deployment Checklist

Before deploying to production:

- [ ] Configure at least 2 LLM provider API keys
- [ ] Set up Redis cache for performance
- [ ] Configure appropriate resource limits
- [ ] Set up monitoring and alerting
- [ ] Configure rate limiting
- [ ] Enable HTTPS/TLS
- [ ] Set up log aggregation
- [ ] Configure backup strategy
- [ ] Test disaster recovery
- [ ] Document runbooks

## 🆘 Support

- GitHub Issues: https://github.com/rhoska/prompt-sentinel/issues
- Documentation: https://docs.promptsentinel.ai
- Docker Hub: https://hub.docker.com/r/promptsentinel/prompt-sentinel

---

*Last Updated: August 2025*  
*Version: 1.0.0*