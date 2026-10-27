terraform {
  required_version = ">= 1.9.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 6.0" }
  }
}
variable "name" {
  type    = string
  default = "heteronet-http-member"
}
variable "cluster_arn" { type = string }
variable "subnet_ids" { type = list(string) }
variable "security_group_ids" { type = list(string) }
variable "execution_role_arn" {
  description = "Existing execution role allowed to pull the image, write logs and read only the join-token secret."
  type        = string
}
variable "join_token_secret_arn" {
  description = "Existing Secrets Manager/SSM secret ARN, not a secret value."
  type        = string
}
variable "endpoint" {
  type = string
  validation {
    condition     = can(regex("^https://[^/?#]+$", var.endpoint))
    error_message = "Enrollment requires an HTTPS control-plane origin."
  }
}
variable "image" {
  type = string
  validation {
    condition     = can(regex("@sha256:[a-f0-9]{64}$", var.image))
    error_message = "Use the tested image's immutable digest."
  }
}
variable "desired_count" {
  type    = number
  default = 1
}
variable "min_count" {
  type    = number
  default = 1
}
variable "max_count" {
  type    = number
  default = 10
}
data "aws_region" "current" {}
resource "aws_cloudwatch_log_group" "member" {
  name              = "/heteronet/${var.name}"
  retention_in_days = 14
}
resource "aws_ecs_task_definition" "member" {
  family                   = var.name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "512"
  memory                   = "1024"
  execution_role_arn       = var.execution_role_arn
  container_definitions = jsonencode([{
    name            = "heteronet", image = var.image, essential = true,
    user            = "65532:65532", readonlyRootFilesystem = true,
    linuxParameters = { capabilities = { drop = ["ALL"] } },
    environment     = [{ name = "HETERONETWORK_ENDPOINT", value = var.endpoint }],
    secrets         = [{ name = "HETERONETWORK_JOIN_TOKEN", valueFrom = var.join_token_secret_arn }],
    logConfiguration = {
      logDriver = "awslogs",
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.member.name,
        "awslogs-region"        = data.aws_region.current.region,
        "awslogs-stream-prefix" = "vpn"
      }
    }
  }])
}
resource "aws_ecs_service" "member" {
  name            = var.name
  cluster         = var.cluster_arn
  task_definition = aws_ecs_task_definition.member.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"
  network_configuration {
    subnets          = var.subnet_ids
    security_groups  = var.security_group_ids
    assign_public_ip = false
  }
  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }
  lifecycle { ignore_changes = [desired_count] }
}
resource "aws_appautoscaling_target" "member" {
  min_capacity       = var.min_count
  max_capacity       = var.max_count
  resource_id        = "service/${split("/", var.cluster_arn)[length(split("/", var.cluster_arn)) - 1]}/${aws_ecs_service.member.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}
resource "aws_appautoscaling_policy" "member" {
  name               = "${var.name}-cpu"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.member.resource_id
  scalable_dimension = aws_appautoscaling_target.member.scalable_dimension
  service_namespace  = aws_appautoscaling_target.member.service_namespace
  target_tracking_scaling_policy_configuration {
    target_value = 60
    predefined_metric_specification { predefined_metric_type = "ECSServiceAverageCPUUtilization" }
  }
}
output "service" { value = aws_ecs_service.member.name }
