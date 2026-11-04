# Shared data directory for API, workers and CronJobs (custody ledgers, key registry, audit log, job
# state): EFS encrypted with a CMK, TLS-only file system policy, one mount target per AZ, an access
# point pinned to uid/gid 10001, automatic AWS Backup.

variable "name" {
  description = "Name prefix."
  type        = string
}

variable "vpc_id" {
  description = "VPC ID."
  type        = string
}

variable "subnet_ids" {
  description = "Private subnets, one per AZ."
  type        = list(string)
}

variable "allowed_security_group_ids" {
  description = "Security groups allowed NFS (2049)."
  type        = list(string)
}

variable "kms_key_arn" {
  description = "KMS key for encryption at rest."
  type        = string
}

variable "tags" {
  description = "Tags for every resource."
  type        = map(string)
  default     = {}
}

resource "aws_efs_file_system" "this" {
  creation_token   = var.name
  encrypted        = true
  kms_key_id       = var.kms_key_arn
  performance_mode = "generalPurpose"
  throughput_mode  = "elastic"

  lifecycle_policy {
    transition_to_ia = "AFTER_30_DAYS"
  }

  protection {
    replication_overwrite = "DISABLED"
  }

  tags = merge(var.tags, { Name = var.name })
}

resource "aws_efs_backup_policy" "this" {
  file_system_id = aws_efs_file_system.this.id
  backup_policy {
    status = "ENABLED"
  }
}

data "aws_iam_policy_document" "fs" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["*"]
    resources = [aws_efs_file_system.this.arn]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
  statement {
    sid       = "MountThroughAccessPointOrCsi"
    actions   = ["elasticfilesystem:ClientMount", "elasticfilesystem:ClientWrite", "elasticfilesystem:ClientRootAccess"]
    resources = [aws_efs_file_system.this.arn]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "elasticfilesystem:AccessedViaMountTarget"
      values   = ["true"]
    }
  }
}

resource "aws_efs_file_system_policy" "this" {
  file_system_id = aws_efs_file_system.this.id
  policy         = data.aws_iam_policy_document.fs.json
}

resource "aws_security_group" "this" {
  name        = "${var.name}-efs"
  description = "NFS from the EKS cluster"
  vpc_id      = var.vpc_id
  tags        = merge(var.tags, { Name = "${var.name}-efs" })
}

resource "aws_vpc_security_group_ingress_rule" "nfs" {
  for_each = toset(var.allowed_security_group_ids)

  security_group_id            = aws_security_group.this.id
  description                  = "NFS from ${each.value}"
  ip_protocol                  = "tcp"
  from_port                    = 2049
  to_port                      = 2049
  referenced_security_group_id = each.value
}

resource "aws_efs_mount_target" "this" {
  count = length(var.subnet_ids)

  file_system_id  = aws_efs_file_system.this.id
  subnet_id       = var.subnet_ids[count.index]
  security_groups = [aws_security_group.this.id]
}

resource "aws_efs_access_point" "veritas" {
  file_system_id = aws_efs_file_system.this.id

  posix_user {
    uid = 10001
    gid = 10001
  }

  root_directory {
    path = "/veritas"
    creation_info {
      owner_uid   = 10001
      owner_gid   = 10001
      permissions = "0750"
    }
  }

  tags = merge(var.tags, { Name = "${var.name}-veritas" })
}

output "file_system_id" {
  description = "EFS file system ID (StorageClass parameter fileSystemId)."
  value       = aws_efs_file_system.this.id
}

output "file_system_arn" {
  description = "EFS file system ARN (AWS Backup selection)."
  value       = aws_efs_file_system.this.arn
}

output "access_point_id" {
  description = "Access point for static provisioning (volumeHandle fs-id::fsap-id)."
  value       = aws_efs_access_point.veritas.id
}
