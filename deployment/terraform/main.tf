# PromptSentinel ECS Deployment - Main Configuration
# This is a placeholder template to be refined when the application is ready for production

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# Data sources for existing infrastructure
data "aws_vpc" "main" {
  default = var.use_default_vpc
  id      = var.use_default_vpc ? null : var.vpc_id
}

data "aws_subnets" "private" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.main.id]
  }

  tags = {
    Tier = "Private"
  }
}

data "aws_subnets" "public" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.main.id]
  }

  tags = {
    Tier = "Public"
  }
}

# ECS Cluster
resource "aws_ecs_cluster" "prompt_sentinel" {
  name = "${var.environment}-prompt-sentinel-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = var.tags
}

# CloudWatch Log Group
resource "aws_cloudwatch_log_group" "prompt_sentinel" {
  name              = "/ecs/${var.environment}-prompt-sentinel"
  retention_in_days = var.log_retention_days

  tags = var.tags
}

# ECS Task Execution Role
resource "aws_iam_role" "ecs_task_execution" {
  name = "${var.environment}-prompt-sentinel-execution"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })

  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "ecs_task_execution_policy" {
  role       = aws_iam_role.ecs_task_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# ECS Task Role
resource "aws_iam_role" "ecs_task" {
  name = "${var.environment}-prompt-sentinel-task"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })

  tags = var.tags
}

# Secrets Manager for API Keys
resource "aws_secretsmanager_secret" "api_keys" {
  name                    = "${var.environment}-prompt-sentinel-api-keys"
  recovery_window_in_days = 7

  tags = var.tags
}

resource "aws_secretsmanager_secret_version" "api_keys" {
  secret_id = aws_secretsmanager_secret.api_keys.id
  secret_string = jsonencode({
    ANTHROPIC_API_KEY = var.anthropic_api_key
    OPENAI_API_KEY    = var.openai_api_key
    GEMINI_API_KEY    = var.gemini_api_key
  })
}

# IAM Policy for Secrets Manager access
resource "aws_iam_role_policy" "secrets_access" {
  name = "${var.environment}-prompt-sentinel-secrets"
  role = aws_iam_role.ecs_task_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = aws_secretsmanager_secret.api_keys.arn
      }
    ]
  })
}

# Security Group for ALB
resource "aws_security_group" "alb" {
  name        = "${var.environment}-prompt-sentinel-alb"
  description = "Security group for PromptSentinel ALB"
  vpc_id      = data.aws_vpc.main.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = var.tags
}

# Security Group for ECS Tasks
resource "aws_security_group" "ecs_tasks" {
  name        = "${var.environment}-prompt-sentinel-ecs"
  description = "Security group for PromptSentinel ECS tasks"
  vpc_id      = data.aws_vpc.main.id

  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = var.tags
}

# Application Load Balancer
resource "aws_lb" "prompt_sentinel" {
  name               = "${var.environment}-prompt-sentinel"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets           = data.aws_subnets.public.ids

  enable_deletion_protection = var.enable_deletion_protection
  enable_http2              = true

  tags = var.tags
}

# ALB Target Group
resource "aws_lb_target_group" "prompt_sentinel" {
  name        = "${var.environment}-prompt-sentinel"
  port        = 8080
  protocol    = "HTTP"
  vpc_id      = data.aws_vpc.main.id
  target_type = "ip"

  health_check {
    enabled             = true
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 5
    interval            = 30
    path                = "/health"
    matcher             = "200"
  }

  deregistration_delay = 30

  tags = var.tags
}

# ALB Listener
resource "aws_lb_listener" "prompt_sentinel" {
  load_balancer_arn = aws_lb.prompt_sentinel.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.prompt_sentinel.arn
  }
}

# ECS Task Definition
resource "aws_ecs_task_definition" "prompt_sentinel" {
  family                   = "${var.environment}-prompt-sentinel"
  network_mode            = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                     = var.task_cpu
  memory                  = var.task_memory
  execution_role_arn      = aws_iam_role.ecs_task_execution.arn
  task_role_arn           = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([
    {
      name  = "prompt-sentinel"
      image = var.container_image

      environment = [
        {
          name  = "API_ENV"
          value = var.environment
        },
        {
          name  = "DETECTION_MODE"
          value = var.detection_mode
        },
        {
          name  = "LOG_LEVEL"
          value = var.log_level
        },
        {
          name  = "REDIS_ENABLED"
          value = tostring(var.redis_enabled)
        },
        {
          name  = "REDIS_HOST"
          value = var.redis_enabled ? aws_elasticache_cluster.redis[0].cache_nodes[0].address : ""
        }
      ]

      secrets = [
        {
          name      = "ANTHROPIC_API_KEY"
          valueFrom = "${aws_secretsmanager_secret.api_keys.arn}:ANTHROPIC_API_KEY::"
        },
        {
          name      = "OPENAI_API_KEY"
          valueFrom = "${aws_secretsmanager_secret.api_keys.arn}:OPENAI_API_KEY::"
        },
        {
          name      = "GEMINI_API_KEY"
          valueFrom = "${aws_secretsmanager_secret.api_keys.arn}:GEMINI_API_KEY::"
        }
      ]

      portMappings = [
        {
          containerPort = 8080
          protocol      = "tcp"
        }
      ]

      healthCheck = {
        command     = ["CMD-SHELL", "curl -f http://localhost:8080/health || exit 1"]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 60
      }

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.prompt_sentinel.name
          awslogs-region        = var.aws_region
          awslogs-stream-prefix = "ecs"
        }
      }
    }
  ])

  tags = var.tags
}

# ECS Service
resource "aws_ecs_service" "prompt_sentinel" {
  name            = "${var.environment}-prompt-sentinel"
  cluster         = aws_ecs_cluster.prompt_sentinel.id
  task_definition = aws_ecs_task_definition.prompt_sentinel.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  network_configuration {
    security_groups  = [aws_security_group.ecs_tasks.id]
    subnets         = data.aws_subnets.private.ids
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.prompt_sentinel.arn
    container_name   = "prompt-sentinel"
    container_port   = 8080
  }

  depends_on = [
    aws_lb_listener.prompt_sentinel,
    aws_iam_role_policy.secrets_access
  ]

  tags = var.tags
}

# Auto Scaling
resource "aws_appautoscaling_target" "prompt_sentinel" {
  max_capacity       = var.max_capacity
  min_capacity       = var.min_capacity
  resource_id        = "service/${aws_ecs_cluster.prompt_sentinel.name}/${aws_ecs_service.prompt_sentinel.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "cpu_scaling" {
  name               = "${var.environment}-prompt-sentinel-cpu"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.prompt_sentinel.resource_id
  scalable_dimension = aws_appautoscaling_target.prompt_sentinel.scalable_dimension
  service_namespace  = aws_appautoscaling_target.prompt_sentinel.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    target_value = var.cpu_target_value
  }
}

# Optional: ElastiCache Redis
resource "aws_elasticache_subnet_group" "redis" {
  count      = var.redis_enabled ? 1 : 0
  name       = "${var.environment}-prompt-sentinel"
  subnet_ids = data.aws_subnets.private.ids

  tags = var.tags
}

resource "aws_security_group" "redis" {
  count       = var.redis_enabled ? 1 : 0
  name        = "${var.environment}-prompt-sentinel-redis"
  description = "Security group for PromptSentinel Redis"
  vpc_id      = data.aws_vpc.main.id

  ingress {
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs_tasks.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = var.tags
}

resource "aws_elasticache_cluster" "redis" {
  count                = var.redis_enabled ? 1 : 0
  cluster_id           = "${var.environment}-prompt-sentinel"
  engine              = "redis"
  node_type           = var.redis_node_type
  num_cache_nodes     = 1
  parameter_group_name = "default.redis7"
  engine_version      = "7.0"
  port                = 6379
  subnet_group_name   = aws_elasticache_subnet_group.redis[0].name
  security_group_ids  = [aws_security_group.redis[0].id]

  tags = var.tags
}