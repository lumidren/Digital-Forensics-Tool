# Internet-facing ALB in front of ingress-nginx, protected by AWS WAF:
# * HTTP redirects to HTTPS; HTTPS terminates with an ACM certificate (TLS 1.2+ policy) and re-encrypts
#   to ingress-nginx, which presents the cert-manager certificate (end-to-end TLS);
# * target group of type `ip`, bound to the ingress-nginx Service by the AWS Load Balancer Controller
#   (TargetGroupBinding, see docs/RUNBOOK.md "Platform add-ons");
# * WAF web ACL: AWS managed rule groups (common, known bad inputs, SQLi, Linux, IP reputation,
#   anonymous IP) plus a per-IP rate limit; evidence uploads are exempt from the body-size rule only;
# * ALB access logs and WAF logs retained and encrypted.

variable "name" {
  description = "Name prefix."
  type        = string
}

variable "vpc_id" {
  description = "VPC ID."
  type        = string
}

variable "vpc_cidr" {
  description = "VPC CIDR (ALB egress to targets)."
  type        = string
}

variable "public_subnet_ids" {
  description = "Public subnets for the ALB."
  type        = list(string)
}

variable "certificate_arn" {
  description = "ACM certificate for the HTTPS listener."
  type        = string
}

variable "allowed_cidrs" {
  description = "Client CIDRs allowed to reach the ALB."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "rate_limit_per_5min" {
  description = "Requests per 5 minutes per client IP before WAF blocks."
  type        = number
  default     = 2000
}

variable "log_bucket" {
  description = "Bucket for ALB access logs."
  type        = string
}

variable "logs_kms_key_arn" {
  description = "KMS key for the WAF log group."
  type        = string
}

variable "log_retention_days" {
  description = "WAF log retention."
  type        = number
  default     = 365
}

variable "deletion_protection" {
  description = "Protect the ALB from deletion."
  type        = bool
  default     = true
}

variable "tags" {
  description = "Tags for every resource."
  type        = map(string)
  default     = {}
}

resource "aws_security_group" "alb" {
  name        = "${var.name}-alb"
  description = "Public HTTPS to the Veritas ALB"
  vpc_id      = var.vpc_id
  tags        = merge(var.tags, { Name = "${var.name}-alb" })
}

resource "aws_vpc_security_group_ingress_rule" "https" {
  for_each = toset(var.allowed_cidrs)

  security_group_id = aws_security_group.alb.id
  description       = "HTTPS"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = each.value
}

resource "aws_vpc_security_group_ingress_rule" "http" {
  for_each = toset(var.allowed_cidrs)

  security_group_id = aws_security_group.alb.id
  description       = "HTTP (redirected to HTTPS)"
  ip_protocol       = "tcp"
  from_port         = 80
  to_port           = 80
  cidr_ipv4         = each.value
}

resource "aws_vpc_security_group_egress_rule" "targets" {
  security_group_id = aws_security_group.alb.id
  description       = "HTTPS to ingress-nginx pods"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = var.vpc_cidr
}

resource "aws_lb" "this" {
  name                       = var.name
  load_balancer_type         = "application"
  internal                   = false
  subnets                    = var.public_subnet_ids
  security_groups            = [aws_security_group.alb.id]
  drop_invalid_header_fields = true
  enable_deletion_protection = var.deletion_protection
  idle_timeout               = 3600
  desync_mitigation_mode     = "strictest"

  access_logs {
    bucket  = var.log_bucket
    prefix  = "alb"
    enabled = true
  }

  tags = var.tags
}

resource "aws_lb_target_group" "ingress" {
  name                 = "${var.name}-ingress"
  port                 = 443
  protocol             = "HTTPS"
  target_type          = "ip"
  vpc_id               = var.vpc_id
  deregistration_delay = 60

  health_check {
    enabled             = true
    protocol            = "HTTPS"
    path                = "/healthz"
    matcher             = "200-404"
    interval            = 15
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }

  tags = var.tags
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.this.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }

  tags = var.tags
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.ingress.arn
  }

  tags = var.tags
}

# ---------------------------------------------------------------- WAF
locals {
  managed_rule_groups = [
    { name = "AWSManagedRulesAmazonIpReputationList", priority = 10 },
    { name = "AWSManagedRulesAnonymousIpList", priority = 20 },
    { name = "AWSManagedRulesKnownBadInputsRuleSet", priority = 30 },
    { name = "AWSManagedRulesSQLiRuleSet", priority = 40 },
    { name = "AWSManagedRulesLinuxRuleSet", priority = 50 },
  ]
}

resource "aws_wafv2_web_acl" "this" {
  name        = var.name
  description = "Veritas edge protection"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "rate-limit-per-ip"
    priority = 1
    action {
      block {}
    }
    statement {
      rate_based_statement {
        limit              = var.rate_limit_per_5min
        aggregate_key_type = "IP"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name}-rate-limit"
      sampled_requests_enabled   = true
    }
  }

  # Common rule set; the 8 KB body limit is counted (not blocked) because evidence uploads are large.
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 5
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesCommonRuleSet"
        rule_action_override {
          name = "SizeRestrictions_BODY"
          action_to_use {
            count {}
          }
        }
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name}-common"
      sampled_requests_enabled   = true
    }
  }

  dynamic "rule" {
    for_each = local.managed_rule_groups
    content {
      name     = rule.value.name
      priority = rule.value.priority
      override_action {
        none {}
      }
      statement {
        managed_rule_group_statement {
          vendor_name = "AWS"
          name        = rule.value.name
        }
      }
      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${var.name}-${rule.value.name}"
        sampled_requests_enabled   = true
      }
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = var.name
    sampled_requests_enabled   = true
  }

  tags = var.tags
}

resource "aws_wafv2_web_acl_association" "alb" {
  resource_arn = aws_lb.this.arn
  web_acl_arn  = aws_wafv2_web_acl.this.arn
}

resource "aws_cloudwatch_log_group" "waf" {
  # WAF requires the aws-waf-logs- prefix.
  name              = "aws-waf-logs-${var.name}"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.logs_kms_key_arn
  tags              = var.tags
}

resource "aws_wafv2_web_acl_logging_configuration" "this" {
  resource_arn            = aws_wafv2_web_acl.this.arn
  log_destination_configs = [aws_cloudwatch_log_group.waf.arn]

  redacted_fields {
    single_header {
      name = "authorization"
    }
  }
  redacted_fields {
    single_header {
      name = "cookie"
    }
  }
}

output "alb_arn" {
  description = "ALB ARN."
  value       = aws_lb.this.arn
}

output "alb_arn_suffix" {
  description = "ALB ARN suffix (CloudWatch dimension)."
  value       = aws_lb.this.arn_suffix
}

output "alb_dns_name" {
  description = "ALB DNS name."
  value       = aws_lb.this.dns_name
}

output "alb_zone_id" {
  description = "ALB hosted zone ID (Route 53 alias)."
  value       = aws_lb.this.zone_id
}

output "alb_security_group_id" {
  description = "ALB security group (allowed into the cluster on 443)."
  value       = aws_security_group.alb.id
}

output "target_group_arn" {
  description = "Target group for the ingress-nginx TargetGroupBinding."
  value       = aws_lb_target_group.ingress.arn
}

output "web_acl_name" {
  description = "WAF web ACL name (CloudWatch dimension)."
  value       = aws_wafv2_web_acl.this.name
}
