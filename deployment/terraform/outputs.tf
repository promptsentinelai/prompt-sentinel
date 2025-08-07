# PromptSentinel ECS Deployment - Outputs

output "alb_dns_name" {
  description = "DNS name of the Application Load Balancer"
  value       = aws_lb.prompt_sentinel.dns_name
}

output "alb_zone_id" {
  description = "Zone ID of the Application Load Balancer"
  value       = aws_lb.prompt_sentinel.zone_id
}

output "service_url" {
  description = "URL to access the PromptSentinel service"
  value       = "http://${aws_lb.prompt_sentinel.dns_name}"
}

output "cluster_name" {
  description = "Name of the ECS cluster"
  value       = aws_ecs_cluster.prompt_sentinel.name
}

output "service_name" {
  description = "Name of the ECS service"
  value       = aws_ecs_service.prompt_sentinel.name
}

output "log_group_name" {
  description = "CloudWatch log group name"
  value       = aws_cloudwatch_log_group.prompt_sentinel.name
}

output "redis_endpoint" {
  description = "Redis endpoint (if enabled)"
  value       = var.redis_enabled ? aws_elasticache_cluster.redis[0].cache_nodes[0].address : null
}

output "security_group_alb_id" {
  description = "Security group ID for ALB"
  value       = aws_security_group.alb.id
}

output "security_group_ecs_id" {
  description = "Security group ID for ECS tasks"
  value       = aws_security_group.ecs_tasks.id
}