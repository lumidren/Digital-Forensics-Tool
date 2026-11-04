# AWS Backup: KMS-encrypted vault with Vault Lock (compliance mode once the grace period ends),
# continuous backups (PITR) for RDS and S3, hourly EFS recovery points, daily snapshots retained
# 35 days and monthly retained 1 year, every recovery point copied to a locked vault in the DR region.

variable "name" {
  description = "Name prefix."
  type        = string
}

variable "kms_key_arn" {
  description = "KMS key for the primary vault."
  type        = string
}

variable "dr_kms_key_arn" {
  description = "KMS key (DR region) for the copy vault."
  type        = string
}

variable "rds_arn" {
  description = "RDS instance ARN."
  type        = string
}

variable "s3_bucket_arns" {
  description = "Buckets protected by continuous S3 backup (evidence, backup archives)."
  type        = list(string)
}

variable "efs_arn" {
  description = "EFS file system ARN (shared data directory)."
  type        = string
}

variable "vault_lock_changeable_days" {
  description = "Grace period (days) before the vault lock becomes immutable (compliance mode)."
  type        = number
  default     = 3
}

variable "min_retention_days" {
  description = "Vault lock minimum retention."
  type        = number
  default     = 7
}

variable "max_retention_days" {
  description = "Vault lock maximum retention."
  type        = number
  default     = 3650
}

variable "tags" {
  description = "Tags for every resource."
  type        = map(string)
  default     = {}
}

data "aws_partition" "current" {}

resource "aws_backup_vault" "primary" {
  name        = "${var.name}-primary"
  kms_key_arn = var.kms_key_arn
  tags        = var.tags
}

resource "aws_backup_vault_lock_configuration" "primary" {
  backup_vault_name   = aws_backup_vault.primary.name
  changeable_for_days = var.vault_lock_changeable_days
  min_retention_days  = var.min_retention_days
  max_retention_days  = var.max_retention_days
}

resource "aws_backup_vault" "dr" {
  provider = aws.dr

  name        = "${var.name}-dr"
  kms_key_arn = var.dr_kms_key_arn
  tags        = var.tags
}

resource "aws_backup_vault_lock_configuration" "dr" {
  provider = aws.dr

  backup_vault_name   = aws_backup_vault.dr.name
  changeable_for_days = var.vault_lock_changeable_days
  min_retention_days  = var.min_retention_days
  max_retention_days  = var.max_retention_days
}

resource "aws_backup_plan" "this" {
  name = var.name

  # Continuous backup: point-in-time restore for RDS and S3 within 35 days.
  rule {
    rule_name                = "continuous"
    target_vault_name        = aws_backup_vault.primary.name
    schedule                 = "cron(0 * * * ? *)"
    enable_continuous_backup = true
    start_window             = 60
    completion_window        = 180
    lifecycle {
      delete_after = 35
    }
    copy_action {
      destination_vault_arn = aws_backup_vault.dr.arn
      lifecycle {
        delete_after = 35
      }
    }
  }

  rule {
    rule_name         = "hourly"
    target_vault_name = aws_backup_vault.primary.name
    schedule          = "cron(15 * * * ? *)"
    start_window      = 60
    completion_window = 120
    lifecycle {
      delete_after = 7
    }
  }

  rule {
    rule_name         = "daily"
    target_vault_name = aws_backup_vault.primary.name
    schedule          = "cron(30 3 * * ? *)"
    start_window      = 60
    completion_window = 360
    lifecycle {
      delete_after = 35
    }
    copy_action {
      destination_vault_arn = aws_backup_vault.dr.arn
      lifecycle {
        delete_after = 35
      }
    }
  }

  rule {
    rule_name         = "monthly"
    target_vault_name = aws_backup_vault.primary.name
    schedule          = "cron(0 5 1 * ? *)"
    start_window      = 60
    completion_window = 720
    lifecycle {
      cold_storage_after = 30
      delete_after       = 365
    }
    copy_action {
      destination_vault_arn = aws_backup_vault.dr.arn
      lifecycle {
        cold_storage_after = 30
        delete_after       = 365
      }
    }
  }

  tags = var.tags
}

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["backup.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "backup" {
  name               = "${var.name}-aws-backup"
  assume_role_policy = data.aws_iam_policy_document.assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "backup" {
  for_each = toset([
    "service-role/AWSBackupServiceRolePolicyForBackup",
    "service-role/AWSBackupServiceRolePolicyForRestores",
    "AWSBackupServiceRolePolicyForS3Backup",
    "AWSBackupServiceRolePolicyForS3Restore",
  ])

  role       = aws_iam_role.backup.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/${each.value}"
}

resource "aws_backup_selection" "this" {
  name         = "${var.name}-veritas"
  plan_id      = aws_backup_plan.this.id
  iam_role_arn = aws_iam_role.backup.arn
  resources    = concat([var.rds_arn, var.efs_arn], var.s3_bucket_arns)
}

output "vault_name" {
  description = "Primary vault name."
  value       = aws_backup_vault.primary.name
}

output "dr_vault_arn" {
  description = "DR-region vault ARN."
  value       = aws_backup_vault.dr.arn
}
