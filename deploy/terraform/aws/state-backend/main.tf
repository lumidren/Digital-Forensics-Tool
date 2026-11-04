# One-time bootstrap of the remote state used by environments/*/backend.hcl: a versioned, KMS-encrypted,
# TLS-only S3 bucket per environment and a DynamoDB lock table. Applied once per account with local state:
#   terraform -chdir=deploy/terraform/aws/state-backend init
#   terraform -chdir=deploy/terraform/aws/state-backend apply

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.70.0, < 6.0.0"
    }
  }
}

variable "region" {
  description = "Region of the state bucket and lock table."
  type        = string
  default     = "eu-west-1"
}

variable "environments" {
  description = "Environments that get a state bucket."
  type        = set(string)
  default     = ["staging", "prod"]
}

provider "aws" {
  region = var.region
}

resource "aws_kms_key" "state" {
  description             = "Veritas Terraform state"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_kms_alias" "state" {
  name          = "alias/veritas-terraform-state"
  target_key_id = aws_kms_key.state.key_id
}

resource "aws_s3_bucket" "state" {
  for_each = var.environments
  bucket   = "veritas-tfstate-${each.key}"
}

resource "aws_s3_bucket_public_access_block" "state" {
  for_each                = var.environments
  bucket                  = aws_s3_bucket.state[each.key].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "state" {
  for_each = var.environments
  bucket   = aws_s3_bucket.state[each.key].id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  for_each = var.environments
  bucket   = aws_s3_bucket.state[each.key].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.state.arn
    }
    bucket_key_enabled = true
  }
}

data "aws_iam_policy_document" "state" {
  for_each = var.environments

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.state[each.key].arn, "${aws_s3_bucket.state[each.key].arn}/*"]
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
}

resource "aws_s3_bucket_policy" "state" {
  for_each   = var.environments
  bucket     = aws_s3_bucket.state[each.key].id
  policy     = data.aws_iam_policy_document.state[each.key].json
  depends_on = [aws_s3_bucket_public_access_block.state]
}

resource "aws_dynamodb_table" "locks" {
  name         = "veritas-terraform-locks"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.state.arn
  }

  point_in_time_recovery {
    enabled = true
  }
}

output "state_buckets" {
  description = "State bucket per environment."
  value       = { for k, v in aws_s3_bucket.state : k => v.id }
}
