#!/bin/bash
# PromptSentinel ECS Deployment Script
# This is a placeholder script to be refined when the application is ready for production

set -e

# Configuration
CLUSTER_NAME="${CLUSTER_NAME:-prompt-sentinel-cluster}"
SERVICE_NAME="${SERVICE_NAME:-prompt-sentinel-service}"
TASK_FAMILY="${TASK_FAMILY:-prompt-sentinel}"
AWS_REGION="${AWS_REGION:-us-east-1}"
ECR_REPOSITORY="${ECR_REPOSITORY:-prompt-sentinel}"
IMAGE_TAG="${IMAGE_TAG:-latest}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    if ! command -v aws &> /dev/null; then
        log_error "AWS CLI not found. Please install it first."
        exit 1
    fi
    
    if ! command -v docker &> /dev/null; then
        log_error "Docker not found. Please install it first."
        exit 1
    fi
    
    if ! aws sts get-caller-identity &> /dev/null; then
        log_error "AWS credentials not configured. Please run 'aws configure'."
        exit 1
    fi
    
    log_info "Prerequisites check passed."
}

# Build Docker image
build_image() {
    log_info "Building Docker image..."
    docker build -t ${ECR_REPOSITORY}:${IMAGE_TAG} .
    log_info "Docker image built successfully."
}

# Push to ECR
push_to_ecr() {
    log_info "Pushing image to ECR..."
    
    # Get ECR login token
    aws ecr get-login-password --region ${AWS_REGION} | \
        docker login --username AWS --password-stdin \
        $(aws sts get-caller-identity --query Account --output text).dkr.ecr.${AWS_REGION}.amazonaws.com
    
    # Get or create repository
    if ! aws ecr describe-repositories --repository-names ${ECR_REPOSITORY} --region ${AWS_REGION} &> /dev/null; then
        log_warning "ECR repository doesn't exist. Creating..."
        aws ecr create-repository --repository-name ${ECR_REPOSITORY} --region ${AWS_REGION}
    fi
    
    # Tag and push
    ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
    ECR_URI="${ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_REPOSITORY}"
    
    docker tag ${ECR_REPOSITORY}:${IMAGE_TAG} ${ECR_URI}:${IMAGE_TAG}
    docker push ${ECR_URI}:${IMAGE_TAG}
    
    log_info "Image pushed to ECR successfully."
}

# Update ECS service
update_ecs_service() {
    log_info "Updating ECS service..."
    
    # Force new deployment
    aws ecs update-service \
        --cluster ${CLUSTER_NAME} \
        --service ${SERVICE_NAME} \
        --force-new-deployment \
        --region ${AWS_REGION}
    
    log_info "ECS service update initiated."
    
    # Wait for deployment to stabilize
    log_info "Waiting for service to stabilize..."
    aws ecs wait services-stable \
        --cluster ${CLUSTER_NAME} \
        --services ${SERVICE_NAME} \
        --region ${AWS_REGION}
    
    log_info "ECS service deployed successfully!"
}

# Get service status
get_service_status() {
    log_info "Getting service status..."
    
    aws ecs describe-services \
        --cluster ${CLUSTER_NAME} \
        --services ${SERVICE_NAME} \
        --region ${AWS_REGION} \
        --query 'services[0].{Status:status,RunningCount:runningCount,DesiredCount:desiredCount,PendingCount:pendingCount}' \
        --output table
}

# Main deployment flow
main() {
    log_info "Starting PromptSentinel ECS deployment..."
    
    check_prerequisites
    
    # Parse command line arguments
    case "${1:-deploy}" in
        build)
            build_image
            ;;
        push)
            push_to_ecr
            ;;
        deploy)
            build_image
            push_to_ecr
            update_ecs_service
            get_service_status
            ;;
        update)
            update_ecs_service
            get_service_status
            ;;
        status)
            get_service_status
            ;;
        *)
            echo "Usage: $0 {build|push|deploy|update|status}"
            exit 1
            ;;
    esac
    
    log_info "Operation completed successfully!"
}

# Run main function
main "$@"