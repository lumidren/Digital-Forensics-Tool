# IRSA roles for the Veritas service accounts, least privilege:
#   api     read/write evidence objects, set retention and legal hold, use the evidence key
#   worker  read evidence, write derived objects (no retention or legal-hold changes)
#   ops     list/read evidence metadata for backup manifests, write backup archives under app/
#   clickhouse  write ClickHouse BACKUP files under clickhouse/ in the backup bucket
# No role may delete objects, change bucket configuration or bypass Object Lock.

variable "name" {
  description = "Name prefix."
  type        = string
}

variable "oidc_provider_arn" {
  description = "EKS OIDC provider ARN."
  type        = string
}

variable "oidc_provider_host" {
  description = "EKS OIDC issuer host without scheme."
  type        = string
}

variable "namespace" {
  description = "Namespace of the Veritas release."
  type        = string
}

variable "service_accounts" {
  description = "Service account names (must match the Helm values serviceAccounts.*.name)."
  type = object({
    api        = string
    worker     = string
    ops        = string
    clickhouse = string
  })
}

variable "clickhouse_namespace" {
  description = "Namespace of the ClickHouse release."
  type        = string
}

variable "evidence_bucket_arn" {
  description = "Evidence bucket ARN."
  type        = string
}

variable "backup_bucket_arn" {
  description = "Backup archive bucket ARN."
  type        = string
}

variable "evidence_kms_key_arn" {
  description = "Evidence bucket KMS key."
  type        = string
}

variable "backup_kms_key_arn" {
  description = "Backup bucket KMS key."
  type        = string
}

variable "tags" {
  description = "Tags for every resource."
  type        = map(string)
  default     = {}
}

locals {
  subjects = {
    api        = "system:serviceaccount:${var.namespace}:${var.service_accounts.api}"
    worker     = "system:serviceaccount:${var.namespace}:${var.service_accounts.worker}"
    ops        = "system:serviceaccount:${var.namespace}:${var.service_accounts.ops}"
    clickhouse = "system:serviceaccount:${var.clickhouse_namespace}:${var.service_accounts.clickhouse}"
  }
  evidence_objects = "${var.evidence_bucket_arn}/*"
}

data "aws_iam_policy_document" "assume" {
  for_each = local.subjects

  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [var.oidc_provider_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "${var.oidc_provider_host}:sub"
      values   = [each.value]
    }
    condition {
      test     = "StringEquals"
      variable = "${var.oidc_provider_host}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "this" {
  for_each = local.subjects

  name                 = "${var.name}-${each.key}"
  assume_role_policy   = data.aws_iam_policy_document.assume[each.key].json
  max_session_duration = 3600
  tags                 = var.tags
}

data "aws_iam_policy_document" "api" {
  statement {
    sid       = "BucketRead"
    actions   = ["s3:ListBucket", "s3:GetBucketLocation", "s3:GetBucketObjectLockConfiguration", "s3:GetBucketVersioning"]
    resources = [var.evidence_bucket_arn]
  }
  statement {
    sid = "EvidenceObjects"
    actions = [
      "s3:PutObject", "s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectAttributes",
      "s3:GetObjectRetention", "s3:PutObjectRetention", "s3:GetObjectLegalHold", "s3:PutObjectLegalHold",
    ]
    resources = [local.evidence_objects]
  }
  statement {
    sid       = "EvidenceKey"
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
    resources = [var.evidence_kms_key_arn]
  }
}

data "aws_iam_policy_document" "worker" {
  statement {
    sid       = "BucketRead"
    actions   = ["s3:ListBucket", "s3:GetBucketObjectLockConfiguration"]
    resources = [var.evidence_bucket_arn]
  }
  statement {
    sid       = "EvidenceObjects"
    actions   = ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject"]
    resources = [local.evidence_objects]
  }
  statement {
    sid       = "EvidenceKey"
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
    resources = [var.evidence_kms_key_arn]
  }
}

data "aws_iam_policy_document" "ops" {
  statement {
    sid       = "EvidenceInventory"
    actions   = ["s3:ListBucket", "s3:GetBucketObjectLockConfiguration"]
    resources = [var.evidence_bucket_arn]
  }
  statement {
    sid       = "EvidenceMetadata"
    actions   = ["s3:GetObject", "s3:GetObjectAttributes", "s3:GetObjectRetention"]
    resources = [local.evidence_objects]
  }
  statement {
    sid       = "EvidenceKeyDecrypt"
    actions   = ["kms:Decrypt", "kms:DescribeKey"]
    resources = [var.evidence_kms_key_arn]
  }
  statement {
    sid       = "BackupArchives"
    actions   = ["s3:PutObject"]
    resources = ["${var.backup_bucket_arn}/app/*"]
  }
  statement {
    sid       = "BackupKey"
    actions   = ["kms:Encrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
    resources = [var.backup_kms_key_arn]
  }
}

data "aws_iam_policy_document" "clickhouse" {
  statement {
    sid       = "BackupList"
    actions   = ["s3:ListBucket"]
    resources = [var.backup_bucket_arn]
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["clickhouse/*"]
    }
  }
  statement {
    sid       = "BackupObjects"
    actions   = ["s3:PutObject", "s3:GetObject"]
    resources = ["${var.backup_bucket_arn}/clickhouse/*"]
  }
  statement {
    sid       = "BackupKey"
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
    resources = [var.backup_kms_key_arn]
  }
}

locals {
  policies = {
    api        = data.aws_iam_policy_document.api.json
    worker     = data.aws_iam_policy_document.worker.json
    ops        = data.aws_iam_policy_document.ops.json
    clickhouse = data.aws_iam_policy_document.clickhouse.json
  }
}

resource "aws_iam_role_policy" "this" {
  for_each = local.policies

  name   = "veritas-${each.key}"
  role   = aws_iam_role.this[each.key].id
  policy = each.value
}

output "role_arns" {
  description = "Role ARN per service account (Helm serviceAccounts.*.roleArn)."
  value       = { for k, v in aws_iam_role.this : k => v.arn }
}
