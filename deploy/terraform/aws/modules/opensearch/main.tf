# Optional Amazon OpenSearch domain (enable_opensearch in the stack). The Veritas timeline uses
# ClickHouse; OpenSearch is offered for organisations that centralise log search there. VPC-only,
# encrypted at rest with a CMK, node-to-node TLS, HTTPS with TLS 1.2+, fine-grained access control
# with an IAM master role, audit/application/slow logs to encrypted log groups.

variable "name" {
  description = "Domain name (max 28 characters)."
  type        = string
}

variable "engine_version" {
  description = "OpenSearch engine version."
  type        = string
  default     = "OpenSearch_2.15"
}

variable "vpc_id" {
  description = "VPC ID."
  type        = string
}

variable "subnet_ids" {
  description = "Three private subnets (zone awareness)."
  type        = list(string)
}

variable "allowed_security_group_ids" {
  description = "Security groups allowed HTTPS to the domain."
  type        = list(string)
}

variable "kms_key_arn" {
  description = "KMS key for encryption at rest."
  type        = string
}

variable "logs_kms_key_arn" {
  description = "KMS key for the log groups."
  type        = string
}

variable "master_role_arn" {
  description = "IAM role mapped as the fine-grained access control master user."
  type        = string
}

variable "instance_type" {
  description = "Data node instance type."
  type        = string
  default     = "r6g.large.search"
}

variable "instance_count" {
  description = "Data nodes (multiple of 3)."
  type        = number
  default     = 3
}

variable "volume_size_gb" {
  description = "EBS volume per data node."
  type        = number
  default     = 200
}

variable "tags" {
  description = "Tags for every resource."
  type        = map(string)
  default     = {}
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

resource "aws_security_group" "this" {
  name        = "${var.name}-opensearch"
  description = "HTTPS to OpenSearch from the cluster"
  vpc_id      = var.vpc_id
  tags        = merge(var.tags, { Name = "${var.name}-opensearch" })
}

resource "aws_vpc_security_group_ingress_rule" "https" {
  for_each = toset(var.allowed_security_group_ids)

  security_group_id            = aws_security_group.this.id
  description                  = "HTTPS from ${each.value}"
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  referenced_security_group_id = each.value
}

resource "aws_cloudwatch_log_group" "this" {
  for_each = toset(["audit", "application", "index-slow", "search-slow"])

  name              = "/aws/opensearch/${var.name}/${each.key}"
  retention_in_days = 365
  kms_key_id        = var.logs_kms_key_arn
  tags              = var.tags
}

data "aws_iam_policy_document" "logs" {
  statement {
    actions   = ["logs:PutLogEvents", "logs:CreateLogStream"]
    resources = [for g in aws_cloudwatch_log_group.this : "${g.arn}:*"]
    principals {
      type        = "Service"
      identifiers = ["es.amazonaws.com"]
    }
  }
}

resource "aws_cloudwatch_log_resource_policy" "this" {
  policy_name     = "${var.name}-opensearch"
  policy_document = data.aws_iam_policy_document.logs.json
}

data "aws_iam_policy_document" "access" {
  statement {
    actions   = ["es:ESHttp*"]
    resources = ["arn:${data.aws_partition.current.partition}:es:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:domain/${var.name}/*"]
    principals {
      type        = "AWS"
      identifiers = [var.master_role_arn]
    }
  }
}

resource "aws_opensearch_domain" "this" {
  domain_name     = var.name
  engine_version  = var.engine_version
  access_policies = data.aws_iam_policy_document.access.json

  cluster_config {
    instance_type          = var.instance_type
    instance_count         = var.instance_count
    zone_awareness_enabled = true
    zone_awareness_config {
      availability_zone_count = 3
    }
    dedicated_master_enabled = true
    dedicated_master_type    = "m6g.large.search"
    dedicated_master_count   = 3
  }

  ebs_options {
    ebs_enabled = true
    volume_type = "gp3"
    volume_size = var.volume_size_gb
  }

  vpc_options {
    subnet_ids         = var.subnet_ids
    security_group_ids = [aws_security_group.this.id]
  }

  encrypt_at_rest {
    enabled    = true
    kms_key_id = var.kms_key_arn
  }

  node_to_node_encryption {
    enabled = true
  }

  domain_endpoint_options {
    enforce_https       = true
    tls_security_policy = "Policy-Min-TLS-1-2-PFS-2023-10"
  }

  advanced_security_options {
    enabled                        = true
    anonymous_auth_enabled         = false
    internal_user_database_enabled = false
    master_user_options {
      master_user_arn = var.master_role_arn
    }
  }

  dynamic "log_publishing_options" {
    for_each = {
      AUDIT_LOGS          = "audit"
      ES_APPLICATION_LOGS = "application"
      INDEX_SLOW_LOGS     = "index-slow"
      SEARCH_SLOW_LOGS    = "search-slow"
    }
    content {
      log_type                 = log_publishing_options.key
      cloudwatch_log_group_arn = aws_cloudwatch_log_group.this[log_publishing_options.value].arn
    }
  }

  tags       = var.tags
  depends_on = [aws_cloudwatch_log_resource_policy.this]
}

output "endpoint" {
  description = "Domain HTTPS endpoint."
  value       = aws_opensearch_domain.this.endpoint
}
