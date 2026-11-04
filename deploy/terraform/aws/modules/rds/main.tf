# Case database: PostgreSQL 16, Multi-AZ, KMS-encrypted storage and Performance Insights, 35 days of
# automated backups (point-in-time recovery to any second inside the window, transaction logs shipped
# every 5 minutes), deletion protection, TLS enforced, master password managed in Secrets Manager.

variable "name" {
  description = "Identifier prefix."
  type        = string
}

variable "vpc_id" {
  description = "VPC ID."
  type        = string
}

variable "subnet_ids" {
  description = "Isolated database subnets."
  type        = list(string)
}

variable "allowed_security_group_ids" {
  description = "Security groups allowed to connect on 5432 (EKS cluster/node security group)."
  type        = list(string)
}

variable "kms_key_arn" {
  description = "KMS key for storage, Performance Insights and the managed master secret."
  type        = string
}

variable "engine_version" {
  description = "PostgreSQL 16 minor version."
  type        = string
  default     = "16.4"
}

variable "instance_class" {
  description = "DB instance class."
  type        = string
  default     = "db.r6g.large"
}

variable "allocated_storage_gb" {
  description = "Initial storage."
  type        = number
  default     = 100
}

variable "max_allocated_storage_gb" {
  description = "Storage autoscaling ceiling."
  type        = number
  default     = 1000
}

variable "backup_retention_days" {
  description = "Automated backup retention (PITR window). 35 is the RDS maximum."
  type        = number
  default     = 35
}

variable "deletion_protection" {
  description = "Refuse deletion of the instance."
  type        = bool
  default     = true
}

variable "tags" {
  description = "Tags for every resource."
  type        = map(string)
  default     = {}
}

data "aws_partition" "current" {}

resource "aws_db_subnet_group" "this" {
  name       = var.name
  subnet_ids = var.subnet_ids
  tags       = var.tags
}

resource "aws_security_group" "this" {
  name        = "${var.name}-postgres"
  description = "PostgreSQL from the EKS cluster only"
  vpc_id      = var.vpc_id
  tags        = merge(var.tags, { Name = "${var.name}-postgres" })
}

resource "aws_vpc_security_group_ingress_rule" "postgres" {
  for_each = toset(var.allowed_security_group_ids)

  security_group_id            = aws_security_group.this.id
  description                  = "PostgreSQL from ${each.value}"
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  referenced_security_group_id = each.value
}

resource "aws_db_parameter_group" "this" {
  name   = "${var.name}-pg16"
  family = "postgres16"
  tags   = var.tags

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }
  parameter {
    name  = "log_connections"
    value = "1"
  }
  parameter {
    name  = "log_disconnections"
    value = "1"
  }
  parameter {
    name  = "log_min_duration_statement"
    value = "1000"
  }
  parameter {
    name  = "password_encryption"
    value = "scram-sha-256"
  }
}

data "aws_iam_policy_document" "monitoring_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["monitoring.rds.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "monitoring" {
  name               = "${var.name}-rds-monitoring"
  assume_role_policy = data.aws_iam_policy_document.monitoring_assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "monitoring" {
  role       = aws_iam_role.monitoring.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

resource "aws_db_instance" "this" {
  identifier                            = var.name
  engine                                = "postgres"
  engine_version                        = var.engine_version
  instance_class                        = var.instance_class
  db_name                               = "veritas"
  username                              = "veritas_admin"
  manage_master_user_password           = true
  master_user_secret_kms_key_id         = var.kms_key_arn
  allocated_storage                     = var.allocated_storage_gb
  max_allocated_storage                 = var.max_allocated_storage_gb
  storage_type                          = "gp3"
  storage_encrypted                     = true
  kms_key_id                            = var.kms_key_arn
  multi_az                              = true
  db_subnet_group_name                  = aws_db_subnet_group.this.name
  vpc_security_group_ids                = [aws_security_group.this.id]
  parameter_group_name                  = aws_db_parameter_group.this.name
  publicly_accessible                   = false
  iam_database_authentication_enabled   = true
  backup_retention_period               = var.backup_retention_days
  backup_window                         = "02:00-03:00"
  maintenance_window                    = "sun:04:00-sun:05:00"
  copy_tags_to_snapshot                 = true
  delete_automated_backups              = false
  deletion_protection                   = var.deletion_protection
  skip_final_snapshot                   = false
  final_snapshot_identifier             = "${var.name}-final"
  auto_minor_version_upgrade            = true
  performance_insights_enabled          = true
  performance_insights_kms_key_id       = var.kms_key_arn
  performance_insights_retention_period = 7
  monitoring_interval                   = 30
  monitoring_role_arn                   = aws_iam_role.monitoring.arn
  enabled_cloudwatch_logs_exports       = ["postgresql", "upgrade"]
  ca_cert_identifier                    = "rds-ca-rsa2048-g1"
  tags                                  = var.tags
}

output "instance_arn" {
  description = "DB instance ARN (AWS Backup selection, cross-region backup replication)."
  value       = aws_db_instance.this.arn
}

output "instance_id" {
  description = "DB instance identifier (CloudWatch alarm dimension)."
  value       = aws_db_instance.this.identifier
}

output "endpoint" {
  description = "host:port of the writer."
  value       = aws_db_instance.this.endpoint
}

output "master_user_secret_arn" {
  description = "Secrets Manager secret holding the master credentials (rotated by RDS)."
  value       = aws_db_instance.this.master_user_secret[0].secret_arn
}

output "security_group_id" {
  description = "Database security group."
  value       = aws_security_group.this.id
}
