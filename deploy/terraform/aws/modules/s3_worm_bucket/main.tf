# WORM bucket for evidence (and, with a shorter retention, for encrypted application backups):
# * Object Lock in COMPLIANCE mode with a default retention: no principal, including root, can delete
#   or overwrite a locked object version before its retention date;
# * versioning (required by Object Lock), SSE-KMS with a per-environment key and S3 Bucket Keys;
# * bucket policy denying non-TLS requests, TLS < 1.2, and PutObject without server-side encryption;
# * server access logging to the central log bucket;
# * optional cross-region replication (with Replication Time Control) into a locked replica bucket in
#   the DR region, encrypted with a DR-region key.

variable "name" {
  description = "Bucket name."
  type        = string
}

variable "kms_key_arn" {
  description = "KMS key for SSE-KMS."
  type        = string
}

variable "retention_days" {
  description = "Default Object Lock COMPLIANCE retention in days."
  type        = number
}

variable "log_bucket" {
  description = "Target bucket for server access logs."
  type        = string
}

variable "writer_role_arns" {
  description = "Roles allowed to write objects (all other principals are denied s3:PutObject)."
  type        = list(string)
  default     = []
}

variable "replication" {
  description = "Cross-region replication target. Null disables replication."
  type = object({
    bucket_name = string
    kms_key_arn = string
  })
  default = null
}

variable "tags" {
  description = "Tags for every resource."
  type        = map(string)
  default     = {}
}


# ---------------------------------------------------------------- primary bucket
resource "aws_s3_bucket" "this" {
  bucket              = var.name
  object_lock_enabled = true
  tags                = var.tags
}

resource "aws_s3_bucket_public_access_block" "this" {
  bucket                  = aws_s3_bucket.this.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "this" {
  bucket = aws_s3_bucket.this.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.this.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "this" {
  bucket = aws_s3_bucket.this.id
  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = var.retention_days
    }
  }
  depends_on = [aws_s3_bucket_versioning.this]
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = aws_s3_bucket.this.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_logging" "this" {
  bucket        = aws_s3_bucket.this.id
  target_bucket = var.log_bucket
  target_prefix = "s3/${var.name}/"
}

data "aws_iam_policy_document" "this" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.this.arn, "${aws_s3_bucket.this.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
  statement {
    sid       = "DenyOldTls"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.this.arn, "${aws_s3_bucket.this.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "NumericLessThan"
      variable = "s3:TlsVersion"
      values   = ["1.2"]
    }
  }
  statement {
    sid       = "DenyUnencryptedPuts"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.this.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Null"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["true"]
    }
  }
  statement {
    sid       = "DenyUnknownEncryption"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.this.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["aws:kms", "AES256"]
    }
    condition {
      test     = "Null"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["false"]
    }
  }
  statement {
    sid       = "DenyLockBypass"
    effect    = "Deny"
    actions   = ["s3:BypassGovernanceRetention", "s3:PutBucketObjectLockConfiguration", "s3:DeleteBucket"]
    resources = [aws_s3_bucket.this.arn, "${aws_s3_bucket.this.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
  dynamic "statement" {
    for_each = length(var.writer_role_arns) > 0 ? [1] : []
    content {
      sid       = "OnlyNamedWritersMayPut"
      effect    = "Deny"
      actions   = ["s3:PutObject"]
      resources = ["${aws_s3_bucket.this.arn}/*"]
      principals {
        type        = "*"
        identifiers = ["*"]
      }
      condition {
        test     = "ArnNotLike"
        variable = "aws:PrincipalArn"
        values   = var.writer_role_arns
      }
    }
  }
}

resource "aws_s3_bucket_policy" "this" {
  bucket = aws_s3_bucket.this.id
  policy = data.aws_iam_policy_document.this.json
  # The policy denies further Object Lock changes, so it is applied after the lock configuration.
  depends_on = [aws_s3_bucket_public_access_block.this, aws_s3_bucket_object_lock_configuration.this]
}

# ---------------------------------------------------------------- replication (DR region)
resource "aws_s3_bucket" "replica" {
  count    = var.replication == null ? 0 : 1
  provider = aws.replica

  bucket              = var.replication.bucket_name
  object_lock_enabled = true
  tags                = merge(var.tags, { Role = "replica" })
}

resource "aws_s3_bucket_public_access_block" "replica" {
  count    = var.replication == null ? 0 : 1
  provider = aws.replica

  bucket                  = aws_s3_bucket.replica[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "replica" {
  count    = var.replication == null ? 0 : 1
  provider = aws.replica

  bucket = aws_s3_bucket.replica[0].id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "replica" {
  count    = var.replication == null ? 0 : 1
  provider = aws.replica

  bucket = aws_s3_bucket.replica[0].id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "replica" {
  count    = var.replication == null ? 0 : 1
  provider = aws.replica

  bucket = aws_s3_bucket.replica[0].id
  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = var.retention_days
    }
  }
  depends_on = [aws_s3_bucket_versioning.replica]
}

resource "aws_s3_bucket_server_side_encryption_configuration" "replica" {
  count    = var.replication == null ? 0 : 1
  provider = aws.replica

  bucket = aws_s3_bucket.replica[0].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.replication.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

data "aws_iam_policy_document" "replica" {
  count = var.replication == null ? 0 : 1

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.replica[0].arn, "${aws_s3_bucket.replica[0].arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
  statement {
    sid       = "DenyLockBypass"
    effect    = "Deny"
    actions   = ["s3:BypassGovernanceRetention", "s3:PutBucketObjectLockConfiguration", "s3:DeleteBucket"]
    resources = [aws_s3_bucket.replica[0].arn, "${aws_s3_bucket.replica[0].arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}

resource "aws_s3_bucket_policy" "replica" {
  count    = var.replication == null ? 0 : 1
  provider = aws.replica

  bucket     = aws_s3_bucket.replica[0].id
  policy     = data.aws_iam_policy_document.replica[0].json
  depends_on = [aws_s3_bucket_public_access_block.replica, aws_s3_bucket_object_lock_configuration.replica]
}

data "aws_iam_policy_document" "replication_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com", "batchoperations.s3.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "replication" {
  count = var.replication == null ? 0 : 1

  name               = "${var.name}-replication"
  assume_role_policy = data.aws_iam_policy_document.replication_assume.json
  tags               = var.tags
}

data "aws_iam_policy_document" "replication" {
  count = var.replication == null ? 0 : 1

  statement {
    actions   = ["s3:GetReplicationConfiguration", "s3:ListBucket", "s3:GetObjectLockConfiguration"]
    resources = [aws_s3_bucket.this.arn]
  }
  statement {
    actions = [
      "s3:GetObjectVersionForReplication", "s3:GetObjectVersionAcl", "s3:GetObjectVersionTagging",
      "s3:GetObjectRetention", "s3:GetObjectLegalHold",
    ]
    resources = ["${aws_s3_bucket.this.arn}/*"]
  }
  statement {
    actions   = ["s3:ReplicateObject", "s3:ReplicateTags", "s3:ObjectOwnerOverrideToBucketOwner"]
    resources = ["${aws_s3_bucket.replica[0].arn}/*"]
  }
  statement {
    actions   = ["kms:Decrypt"]
    resources = [var.kms_key_arn]
  }
  statement {
    actions   = ["kms:Encrypt", "kms:GenerateDataKey"]
    resources = [var.replication.kms_key_arn]
  }
}

resource "aws_iam_role_policy" "replication" {
  count = var.replication == null ? 0 : 1

  name   = "replication"
  role   = aws_iam_role.replication[0].id
  policy = data.aws_iam_policy_document.replication[0].json
}

resource "aws_s3_bucket_replication_configuration" "this" {
  count = var.replication == null ? 0 : 1

  bucket = aws_s3_bucket.this.id
  role   = aws_iam_role.replication[0].arn

  rule {
    id       = "dr-region"
    status   = "Enabled"
    priority = 1
    filter {}

    delete_marker_replication {
      status = "Disabled"
    }

    source_selection_criteria {
      sse_kms_encrypted_objects {
        status = "Enabled"
      }
    }

    destination {
      bucket        = aws_s3_bucket.replica[0].arn
      storage_class = "STANDARD_IA"
      encryption_configuration {
        replica_kms_key_id = var.replication.kms_key_arn
      }
      replication_time {
        status = "Enabled"
        time {
          minutes = 15
        }
      }
      metrics {
        status = "Enabled"
        event_threshold {
          minutes = 15
        }
      }
    }
  }

  depends_on = [aws_s3_bucket_versioning.this, aws_s3_bucket_versioning.replica]
}

output "bucket" {
  description = "Primary bucket name."
  value       = aws_s3_bucket.this.id
}

output "arn" {
  description = "Primary bucket ARN."
  value       = aws_s3_bucket.this.arn
}

output "replica_arn" {
  description = "Replica bucket ARN (null without replication)."
  value       = var.replication == null ? null : aws_s3_bucket.replica[0].arn
}
