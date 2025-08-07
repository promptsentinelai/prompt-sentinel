# PromptSentinel Deployment Guide

This directory contains deployment templates for various platforms and orchestrators. These are **placeholder templates** that demonstrate the intended architecture and will be refined when the application is production-ready.

## 📁 Directory Structure

```
deployment/
├── terraform/        # AWS ECS deployment using Terraform
├── cloudformation/   # AWS ECS deployment using CloudFormation
├── kubernetes/       # Kubernetes manifests for K8s/EKS/GKE/AKS
└── scripts/         # Deployment utility scripts
```

## 🚀 Deployment Options

### 1. AWS ECS with Terraform

The Terraform module deploys PromptSentinel on AWS ECS Fargate with:
- Application Load Balancer (ALB)
- Auto-scaling based on CPU utilization
- Secrets Manager for API keys
- Optional ElastiCache Redis
- CloudWatch logging

#### Prerequisites
- Terraform >= 1.0
- AWS CLI configured
- Existing VPC with public/private subnets

#### Quick Start
```bash
cd deployment/terraform
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your values
terraform init
terraform plan
terraform apply
```

#### Key Variables
- `environment`: dev/staging/prod
- `container_image`: Docker image URL
- `task_cpu`: CPU units (256-4096)
- `task_memory`: Memory in MB
- `desired_count`: Number of tasks
- `redis_enabled`: Enable Redis cache

### 2. AWS ECS with CloudFormation

The CloudFormation template provides similar functionality to Terraform:
- ECS Fargate cluster
- Application Load Balancer
- Auto-scaling configuration
- Secrets Manager integration
- Optional ElastiCache Redis

#### Prerequisites
- AWS CLI configured
- Existing VPC with subnets

#### Quick Start
```bash
aws cloudformation create-stack \
  --stack-name prompt-sentinel-dev \
  --template-body file://deployment/cloudformation/ecs-fargate.yaml \
  --parameters \
    ParameterKey=Environment,ParameterValue=dev \
    ParameterKey=VpcId,ParameterValue=vpc-xxxxx \
    ParameterKey=PrivateSubnetIds,ParameterValue="subnet-xxx,subnet-yyy" \
    ParameterKey=PublicSubnetIds,ParameterValue="subnet-aaa,subnet-bbb" \
    ParameterKey=AnthropicApiKey,ParameterValue=sk-ant-xxxxx \
  --capabilities CAPABILITY_NAMED_IAM
```

### 3. Kubernetes Deployment

The Kubernetes manifests support deployment to any K8s cluster:
- Amazon EKS
- Google GKE
- Azure AKS
- On-premises Kubernetes

#### Components
- **namespace.yaml**: Dedicated namespace
- **configmap.yaml**: Application configuration
- **secret.yaml**: API keys (encode in production!)
- **deployment.yaml**: Main application deployment
- **service.yaml**: ClusterIP and NodePort services
- **ingress.yaml**: NGINX ingress with TLS
- **hpa.yaml**: Horizontal Pod Autoscaler
- **rbac.yaml**: Service account and permissions
- **redis.yaml**: StatefulSet for Redis cache
- **kustomization.yaml**: Kustomize configuration

#### Prerequisites
- Kubernetes cluster (1.20+)
- kubectl configured
- NGINX Ingress Controller (for ingress)
- cert-manager (for TLS)

#### Quick Start
```bash
cd deployment/kubernetes

# Create namespace
kubectl apply -f namespace.yaml

# Edit secret.yaml with your API keys (base64 encode them!)
kubectl apply -f secret.yaml

# Deploy all resources
kubectl apply -k .

# Or deploy individually
kubectl apply -f configmap.yaml
kubectl apply -f rbac.yaml
kubectl apply -f redis.yaml
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml
kubectl apply -f ingress.yaml
kubectl apply -f hpa.yaml
```

#### Verify Deployment
```bash
# Check pods
kubectl get pods -n prompt-sentinel

# Check service
kubectl get svc -n prompt-sentinel

# Check ingress
kubectl get ingress -n prompt-sentinel

# View logs
kubectl logs -n prompt-sentinel -l app=prompt-sentinel

# Port forward for local testing
kubectl port-forward -n prompt-sentinel svc/prompt-sentinel 8080:80
```

## 🔧 Configuration

### Environment Variables

All deployments use these core environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `API_ENV` | Environment (dev/staging/prod) | `production` |
| `DETECTION_MODE` | Detection sensitivity | `strict` |
| `LOG_LEVEL` | Logging verbosity | `INFO` |
| `REDIS_ENABLED` | Enable Redis cache | `false` |
| `ANTHROPIC_API_KEY` | Anthropic API key | Required |
| `OPENAI_API_KEY` | OpenAI API key | Optional |
| `GEMINI_API_KEY` | Google Gemini API key | Optional |

### Resource Requirements

Recommended resource allocations:

| Environment | CPU | Memory | Replicas |
|-------------|-----|--------|----------|
| Development | 256m | 512Mi | 1 |
| Staging | 500m | 1Gi | 2 |
| Production | 1000m | 2Gi | 3+ |

## 🔐 Security Considerations

1. **API Keys**: Always use secret management (Secrets Manager, K8s Secrets)
2. **Network**: Deploy in private subnets with ALB/Ingress in public
3. **TLS**: Always use HTTPS in production
4. **RBAC**: Implement least-privilege access
5. **Security Groups**: Restrict ingress to necessary ports only

## 📊 Monitoring

### CloudWatch (AWS)
- Logs: `/ecs/prompt-sentinel`
- Metrics: CPU, Memory, Request Count
- Alarms: High CPU, Error Rate

### Prometheus (Kubernetes)
```yaml
# Add to deployment.yaml for Prometheus scraping
metadata:
  annotations:
    prometheus.io/scrape: "true"
    prometheus.io/port: "8080"
    prometheus.io/path: "/metrics"
```

## 🔄 CI/CD Integration

### GitHub Actions
```yaml
- name: Deploy to ECS
  run: |
    aws ecs update-service \
      --cluster ${{ env.CLUSTER_NAME }} \
      --service ${{ env.SERVICE_NAME }} \
      --force-new-deployment
```

### GitLab CI
```yaml
deploy:
  script:
    - kubectl set image deployment/prompt-sentinel \
        prompt-sentinel=$CI_REGISTRY_IMAGE:$CI_COMMIT_SHA \
        -n prompt-sentinel
```

## 📝 TODO

These templates are placeholders and need the following before production use:

- [ ] Add authentication/API key management
- [ ] Implement rate limiting
- [ ] Configure monitoring/metrics endpoints
- [ ] Add health check endpoints
- [ ] Set up log aggregation
- [ ] Configure backup strategies
- [ ] Add network policies
- [ ] Implement zero-downtime deployments
- [ ] Add disaster recovery procedures
- [ ] Create runbooks for common issues

## 🤝 Support

For deployment issues:
1. Check application logs
2. Verify environment variables
3. Ensure API keys are valid
4. Check network connectivity
5. Review resource limits

## 📚 Additional Resources

- [AWS ECS Documentation](https://docs.aws.amazon.com/ecs/)
- [Terraform AWS Provider](https://registry.terraform.io/providers/hashicorp/aws/)
- [Kubernetes Documentation](https://kubernetes.io/docs/)
- [Docker Documentation](https://docs.docker.com/)