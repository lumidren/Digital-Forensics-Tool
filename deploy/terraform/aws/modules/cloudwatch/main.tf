# Encrypted log groups with retention, an encrypted SNS alarm topic and CloudWatch alarms for the
# managed services (Prometheus covers the application itself, see deploy/observability).

variable "name" {
  description = "Name prefix."
  type        = string
}

variable "kms_key_arn" {
  description = "KMS key for log groups and the SNS topic."
  type        = string
}

variable "log_retention_days" {
  description = "Retention for application log groups."
  type        = number
  default     = 365
}

variable "alarm_emails" {
  description = "E-mail subscribers of the alarm topic (each must confirm)."
  type        = list(string)
  default     = []
}

variable "rds_instance_id" {
  description = "RDS instance identifier."
  type        = string
}

variable "alb_arn_suffix" {
  description = "ALB ARN suffix."
  type        = string
}

variable "waf_web_acl_name" {
  description = "WAF web ACL name."
  type        = string
}

variable "efs_file_system_id" {
  description = "EFS file system ID."
  type        = string
}

variable "evidence_bucket" {
  description = "Evidence bucket name (replication latency alarm)."
  type        = string
}

variable "replication_enabled" {
  description = "Whether evidence replication is configured (adds the replication alarms)."
  type        = bool
}

variable "replica_bucket" {
  description = "Name of the evidence replica bucket in the DR region (empty without replication)."
  type        = string
  default     = ""
}

variable "backup_vault_name" {
  description = "AWS Backup vault name."
  type        = string
}

variable "tags" {
  description = "Tags for every resource."
  type        = map(string)
  default     = {}
}

resource "aws_cloudwatch_log_group" "app" {
  for_each = toset(["api", "worker", "web", "ops", "audit"])

  name              = "/veritas/${var.name}/${each.key}"
  retention_in_days = each.key == "audit" ? 3653 : var.log_retention_days
  kms_key_id        = var.kms_key_arn
  tags              = var.tags
}

resource "aws_sns_topic" "alarms" {
  name              = "${var.name}-alarms"
  kms_master_key_id = var.kms_key_arn
  tags              = var.tags
}

resource "aws_sns_topic_subscription" "email" {
  for_each = toset(var.alarm_emails)

  topic_arn = aws_sns_topic.alarms.arn
  protocol  = "email"
  endpoint  = each.value
}

locals {
  alarms = {
    rds-cpu-high = {
      namespace = "AWS/RDS", metric = "CPUUtilization", stat = "Average", threshold = 80, op = "GreaterThanThreshold",
      dims      = tomap({ DBInstanceIdentifier = var.rds_instance_id }), periods = 3, desc = "RDS CPU above 80% for 15 minutes", enabled = true
    }
    rds-free-storage-low = {
      namespace = "AWS/RDS", metric = "FreeStorageSpace", stat = "Minimum", threshold = 21474836480, op = "LessThanThreshold",
      dims      = tomap({ DBInstanceIdentifier = var.rds_instance_id }), periods = 1, desc = "RDS free storage below 20 GiB", enabled = true
    }
    rds-freeable-memory-low = {
      namespace = "AWS/RDS", metric = "FreeableMemory", stat = "Minimum", threshold = 536870912, op = "LessThanThreshold",
      dims      = tomap({ DBInstanceIdentifier = var.rds_instance_id }), periods = 3, desc = "RDS freeable memory below 512 MiB", enabled = true
    }
    alb-5xx = {
      namespace = "AWS/ApplicationELB", metric = "HTTPCode_Target_5XX_Count", stat = "Sum", threshold = 50, op = "GreaterThanThreshold",
      dims      = tomap({ LoadBalancer = var.alb_arn_suffix }), periods = 2, desc = "More than 50 target 5xx per 5 minutes", enabled = true
    }
    alb-elb-5xx = {
      namespace = "AWS/ApplicationELB", metric = "HTTPCode_ELB_5XX_Count", stat = "Sum", threshold = 20, op = "GreaterThanThreshold",
      dims      = tomap({ LoadBalancer = var.alb_arn_suffix }), periods = 2, desc = "ALB-generated 5xx (no healthy ingress targets?)", enabled = true
    }
    waf-blocked-spike = {
      namespace = "AWS/WAFV2", metric = "BlockedRequests", stat = "Sum", threshold = 1000, op = "GreaterThanThreshold",
      dims      = tomap({ WebACL = var.waf_web_acl_name, Rule = "ALL", Region = data.aws_region.current.name }), periods = 1, desc = "WAF blocked more than 1000 requests in 5 minutes", enabled = true
    }
    efs-io-limit = {
      namespace = "AWS/EFS", metric = "PercentIOLimit", stat = "Maximum", threshold = 90, op = "GreaterThanThreshold",
      dims      = tomap({ FileSystemId = var.efs_file_system_id }), periods = 3, desc = "EFS close to its I/O limit", enabled = true
    }
    backup-jobs-failed = {
      namespace = "AWS/Backup", metric = "NumberOfBackupJobsFailed", stat = "Sum", threshold = 0, op = "GreaterThanThreshold",
      dims      = tomap({ BackupVaultName = var.backup_vault_name }), periods = 1, desc = "AWS Backup job failed", enabled = true
    }
    backup-copy-jobs-failed = {
      namespace = "AWS/Backup", metric = "NumberOfCopyJobsFailed", stat = "Sum", threshold = 0, op = "GreaterThanThreshold",
      dims      = tomap({ BackupVaultName = var.backup_vault_name }), periods = 1, desc = "AWS Backup cross-region copy failed", enabled = true
    }
    evidence-replication-latency = {
      namespace = "AWS/S3", metric = "ReplicationLatency", stat = "Maximum", threshold = 900, op = "GreaterThanThreshold",
      dims      = tomap({ SourceBucket = var.evidence_bucket, DestinationBucket = var.replica_bucket, RuleId = "dr-region" }), periods = 2,
      desc      = "Evidence replication to the DR region is behind its 15-minute RTC target", enabled = var.replication_enabled
    }
    evidence-replication-failed = {
      namespace = "AWS/S3", metric = "OperationsFailedReplication", stat = "Sum", threshold = 0, op = "GreaterThanThreshold",
      dims      = tomap({ SourceBucket = var.evidence_bucket, DestinationBucket = var.replica_bucket, RuleId = "dr-region" }), periods = 1,
      desc      = "Evidence objects failed to replicate to the DR region", enabled = var.replication_enabled
    }
  }
}

data "aws_region" "current" {}

resource "aws_cloudwatch_metric_alarm" "this" {
  for_each = { for k, v in local.alarms : k => v if v.enabled }

  alarm_name          = "${var.name}-${each.key}"
  alarm_description   = each.value.desc
  namespace           = each.value.namespace
  metric_name         = each.value.metric
  statistic           = each.value.stat
  dimensions          = each.value.dims
  period              = 300
  evaluation_periods  = each.value.periods
  threshold           = each.value.threshold
  comparison_operator = each.value.op
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alarms.arn]
  ok_actions          = [aws_sns_topic.alarms.arn]
  tags                = var.tags
}

output "sns_topic_arn" {
  description = "Alarm topic (also usable as an Alertmanager SNS receiver)."
  value       = aws_sns_topic.alarms.arn
}

output "log_group_names" {
  description = "Application log groups."
  value       = { for k, v in aws_cloudwatch_log_group.app : k => v.name }
}
