# PromptSentinel ECS Deployment - Variables
# This is a placeholder template to be refined when the application is ready for production

variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "vpc_id" {
  description = "VPC ID for deployment (if not using default)"
  type        = string
  default     = ""
}

variable "use_default_vpc" {
  description = "Use the default VPC"
  type        = bool
  default     = false
}

variable "allowed_cidr_blocks" {
  description = "CIDR blocks allowed to access the ALB"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

# Container Configuration
variable "container_image" {
  description = "Docker image for PromptSentinel"
  type        = string
  default     = "promptsentinelai/prompt-sentinel:latest"
}

variable "task_cpu" {
  description = "CPU units for ECS task (256, 512, 1024, 2048, 4096)"
  type        = string
  default     = "512"
}

variable "task_memory" {
  description = "Memory for ECS task in MB"
  type        = string
  default     = "1024"
}

# Auto Scaling Configuration
variable "desired_count" {
  description = "Desired number of ECS tasks"
  type        = number
  default     = 2
}

variable "min_capacity" {
  description = "Minimum number of ECS tasks"
  type        = number
  default     = 1
}

variable "max_capacity" {
  description = "Maximum number of ECS tasks"
  type        = number
  default     = 10
}

variable "cpu_target_value" {
  description = "Target CPU utilization for auto-scaling"
  type        = number
  default     = 70
}

# API Keys (sensitive)
variable "anthropic_api_key" {
  description = "Anthropic API key"
  type        = string
  sensitive   = true
}

variable "openai_api_key" {
  description = "OpenAI API key"
  type        = string
  sensitive   = true
  default     = ""
}

variable "gemini_api_key" {
  description = "Google Gemini API key"
  type        = string
  sensitive   = true
  default     = ""
}

# Application Configuration
variable "detection_mode" {
  description = "Detection mode (strict, moderate, permissive)"
  type        = string
  default     = "strict"
  validation {
    condition     = contains(["strict", "moderate", "permissive"], var.detection_mode)
    error_message = "Detection mode must be strict, moderate, or permissive."
  }
}

variable "log_level" {
  description = "Application log level"
  type        = string
  default     = "INFO"
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days"
  type        = number
  default     = 30
}

# Redis Configuration
variable "redis_enabled" {
  description = "Enable Redis cache"
  type        = bool
  default     = false
}

variable "redis_node_type" {
  description = "ElastiCache Redis node type"
  type        = string
  default     = "cache.t3.micro"
}

# Security
variable "enable_deletion_protection" {
  description = "Enable deletion protection on ALB"
  type        = bool
  default     = false
}

# Tags
variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default = {
    Project     = "PromptSentinel"
    ManagedBy   = "Terraform"
    Purpose     = "Security"
  }
}