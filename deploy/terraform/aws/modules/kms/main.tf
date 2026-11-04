# Customer-managed KMS keys, one per purpose, with annual automatic rotation.
# Key administration stays with the account root (IAM policies delegate); service principals are
# granted only what their integration needs.

variable "name_prefix" {
  description = "Prefix for key aliases, e.g. veritas-prod."
  type        = string
}

variable "keys" {
  description = "Purposes to create keys for. Supported: evidence, rds, eks, logs, backup, efs, secrets, opensearch."
  type        = set(string)
}

variable "deletion_window_in_days" {
  description = "Waiting period before a scheduled key deletion takes effect."
  type        = number
  default     = 30
}

variable "multi_region_keys" {
  description = "Purposes whose keys are created as multi-Region primary keys."
  type        = set(string)
  default     = []
}

variable "tags" {
  description = "Tags applied to every key."
  type        = map(string)
  default     = {}
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

locals {
  account = data.aws_caller_identity.current.account_id
  region  = data.aws_region.current.name
  part    = data.aws_partition.current.partition
  descriptions = {
    evidence   = "Veritas evidence store (S3 Object Lock) SSE-KMS"
    rds        = "Veritas case database (RDS PostgreSQL) storage and Performance Insights"
    eks        = "Veritas EKS secrets envelope encryption and node EBS volumes"
    logs       = "Veritas CloudWatch Logs, VPC flow logs, WAF logs and SNS alarms"
    backup     = "Veritas AWS Backup vault and application backup archives"
    efs        = "Veritas shared data directory (EFS)"
    secrets    = "Veritas Secrets Manager runtime secrets"
    opensearch = "Veritas Amazon OpenSearch domain"
  }
}

data "aws_iam_policy_document" "key" {
  for_each = var.keys

  statement {
    sid       = "AccountAdministration"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${local.part}:iam::${local.account}:root"]
    }
  }

  dynamic "statement" {
    for_each = each.key == "logs" ? [1] : []
    content {
      sid       = "CloudWatchLogs"
      actions   = ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"]
      resources = ["*"]
      principals {
        type        = "Service"
        identifiers = ["logs.${local.region}.amazonaws.com"]
      }
      condition {
        test     = "ArnLike"
        variable = "kms:EncryptionContext:aws:logs:arn"
        values   = ["arn:${local.part}:logs:${local.region}:${local.account}:*"]
      }
    }
  }

  dynamic "statement" {
    for_each = each.key == "logs" ? [1] : []
    content {
      sid       = "CloudWatchAlarmsToEncryptedSns"
      actions   = ["kms:Decrypt", "kms:GenerateDataKey*"]
      resources = ["*"]
      principals {
        type        = "Service"
        identifiers = ["cloudwatch.amazonaws.com"]
      }
    }
  }

  dynamic "statement" {
    for_each = each.key == "eks" ? [1] : []
    content {
      sid       = "AutoScalingEncryptedNodeVolumes"
      actions   = ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey"]
      resources = ["*"]
      principals {
        type        = "AWS"
        identifiers = ["arn:${local.part}:iam::${local.account}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"]
      }
    }
  }

  dynamic "statement" {
    for_each = each.key == "eks" ? [1] : []
    content {
      sid       = "AutoScalingGrants"
      actions   = ["kms:CreateGrant"]
      resources = ["*"]
      principals {
        type        = "AWS"
        identifiers = ["arn:${local.part}:iam::${local.account}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"]
      }
      condition {
        test     = "Bool"
        variable = "kms:GrantIsForAWSResource"
        values   = ["true"]
      }
    }
  }
}

resource "aws_kms_key" "this" {
  for_each = var.keys

  description             = lookup(local.descriptions, each.key, "Veritas ${each.key}")
  enable_key_rotation     = true
  rotation_period_in_days = 365
  deletion_window_in_days = var.deletion_window_in_days
  multi_region            = contains(var.multi_region_keys, each.key)
  policy                  = data.aws_iam_policy_document.key[each.key].json
  tags                    = merge(var.tags, { Name = "${var.name_prefix}-${each.key}", Purpose = each.key })
}

resource "aws_kms_alias" "this" {
  for_each = var.keys

  name          = "alias/${var.name_prefix}-${each.key}"
  target_key_id = aws_kms_key.this[each.key].key_id
}

output "key_arns" {
  description = "Key ARN per purpose."
  value       = { for k, v in aws_kms_key.this : k => v.arn }
}

output "key_ids" {
  description = "Key ID per purpose."
  value       = { for k, v in aws_kms_key.this : k => v.key_id }
}
