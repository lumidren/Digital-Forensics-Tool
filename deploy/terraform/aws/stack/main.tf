# One Veritas environment (cluster profile) on AWS. Called from environments/<env>/main.tf.

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  name    = "veritas-${var.environment}"
  account = data.aws_caller_identity.current.account_id
  part    = data.aws_partition.current.partition
  tags = merge(var.tags, {
    Application = "veritas"
    Environment = var.environment
    ManagedBy   = "terraform"
  })
  service_accounts = {
    api        = "veritas-api"
    worker     = "veritas-worker"
    ops        = "veritas-ops"
    clickhouse = "clickhouse"
  }
  # IRSA role ARNs are deterministic; computing them here lets bucket policies name their writers
  # without a dependency cycle between the buckets and the roles.
  role_arn = { for k in keys(local.service_accounts) : k => "arn:${local.part}:iam::${local.account}:role/${local.name}-${k}" }
  primary_keys = setunion(
    ["evidence", "rds", "eks", "logs", "backup", "efs", "secrets"],
    var.enable_opensearch ? ["opensearch"] : [],
  )
}

# ---------------------------------------------------------------- keys
module "kms" {
  source      = "../modules/kms"
  name_prefix = local.name
  keys        = local.primary_keys
  tags        = local.tags
}

module "kms_dr" {
  source      = "../modules/kms"
  providers   = { aws = aws.dr }
  name_prefix = "${local.name}-dr"
  keys        = ["evidence", "backup", "rds"]
  tags        = local.tags
}

# ---------------------------------------------------------------- network and cluster
module "vpc" {
  source                   = "../modules/vpc"
  name                     = local.name
  cidr                     = var.vpc_cidr
  azs                      = var.azs
  single_nat_gateway       = var.single_nat_gateway
  cluster_name             = local.name
  flow_logs_kms_key_arn    = module.kms.key_arns["logs"]
  flow_logs_retention_days = var.log_retention_days
  tags                     = local.tags
}

module "eks" {
  source                = "../modules/eks"
  name                  = local.name
  kubernetes_version    = var.kubernetes_version
  vpc_id                = module.vpc.vpc_id
  subnet_ids            = module.vpc.private_subnet_ids
  public_access_cidrs   = var.eks_public_access_cidrs
  secrets_kms_key_arn   = module.kms.key_arns["eks"]
  logs_kms_key_arn      = module.kms.key_arns["logs"]
  log_retention_days    = var.log_retention_days
  system_scaling        = var.system_node_scaling
  worker_scaling        = var.worker_node_scaling
  worker_instance_types = var.worker_instance_types
  admin_role_arns       = var.eks_admin_role_arns
  tags                  = local.tags
}

# ---------------------------------------------------------------- data stores
module "rds" {
  source                     = "../modules/rds"
  name                       = local.name
  vpc_id                     = module.vpc.vpc_id
  subnet_ids                 = module.vpc.database_subnet_ids
  allowed_security_group_ids = [module.eks.cluster_security_group_id]
  kms_key_arn                = module.kms.key_arns["rds"]
  instance_class             = var.rds_instance_class
  deletion_protection        = var.deletion_protection
  tags                       = local.tags
}

# Automated backups (snapshots + transaction logs) replicated to the DR region: PITR there too.
resource "aws_db_instance_automated_backups_replication" "dr" {
  provider = aws.dr

  source_db_instance_arn = module.rds.instance_arn
  kms_key_id             = module.kms_dr.key_arns["rds"]
  retention_period       = 14
}

module "logs_bucket" {
  source = "../modules/log_bucket"
  name   = "${local.name}-logs-${local.account}"
  tags   = local.tags
}

module "evidence_bucket" {
  source           = "../modules/s3_worm_bucket"
  providers        = { aws = aws, aws.replica = aws.dr }
  name             = "${local.name}-evidence-${local.account}"
  kms_key_arn      = module.kms.key_arns["evidence"]
  retention_days   = var.evidence_retention_days
  log_bucket       = module.logs_bucket.bucket
  writer_role_arns = [local.role_arn["api"], local.role_arn["worker"]]
  replication = var.enable_replication ? {
    bucket_name = "${local.name}-evidence-${local.account}-replica"
    kms_key_arn = module.kms_dr.key_arns["evidence"]
  } : null
  tags = local.tags
}

module "backup_bucket" {
  source           = "../modules/s3_worm_bucket"
  providers        = { aws = aws, aws.replica = aws.dr }
  name             = "${local.name}-backups-${local.account}"
  kms_key_arn      = module.kms.key_arns["backup"]
  retention_days   = var.backup_archive_retention_days
  log_bucket       = module.logs_bucket.bucket
  writer_role_arns = [local.role_arn["ops"], local.role_arn["clickhouse"]]
  replication = var.enable_replication ? {
    bucket_name = "${local.name}-backups-${local.account}-replica"
    kms_key_arn = module.kms_dr.key_arns["backup"]
  } : null
  tags = local.tags
}

module "efs" {
  source                     = "../modules/efs"
  name                       = local.name
  vpc_id                     = module.vpc.vpc_id
  subnet_ids                 = module.vpc.private_subnet_ids
  allowed_security_group_ids = [module.eks.cluster_security_group_id]
  kms_key_arn                = module.kms.key_arns["efs"]
  tags                       = local.tags
}

module "irsa" {
  source               = "../modules/iam_irsa"
  name                 = local.name
  oidc_provider_arn    = module.eks.oidc_provider_arn
  oidc_provider_host   = module.eks.oidc_provider_host
  namespace            = var.namespace
  clickhouse_namespace = "clickhouse"
  service_accounts     = local.service_accounts
  evidence_bucket_arn  = module.evidence_bucket.arn
  backup_bucket_arn    = module.backup_bucket.arn
  evidence_kms_key_arn = module.kms.key_arns["evidence"]
  backup_kms_key_arn   = module.kms.key_arns["backup"]
  tags                 = local.tags
}

# Runtime secret consumed by External Secrets (keys: VERITAS_DATABASE_URL, VERITAS_TIMELINE_URL,
# VERITAS_MASTER_KEY, VERITAS_SERVICE_KEY_SEED, VERITAS_BACKUP_RECIPIENT). Values are written by the
# key custodians (docs/RUNBOOK.md "Secrets"), never by Terraform, so they never enter the state file.
resource "aws_secretsmanager_secret" "runtime" {
  name                    = "veritas/${var.environment}/runtime"
  kms_key_id              = module.kms.key_arns["secrets"]
  recovery_window_in_days = 30
  tags                    = local.tags
}

# ---------------------------------------------------------------- edge
data "aws_route53_zone" "public" {
  name         = var.route53_zone_name
  private_zone = false
}

resource "aws_acm_certificate" "this" {
  domain_name       = var.domain_name
  validation_method = "DNS"
  tags              = local.tags

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "validation" {
  for_each = { for o in aws_acm_certificate.this.domain_validation_options : o.domain_name => o }

  zone_id         = data.aws_route53_zone.public.zone_id
  name            = each.value.resource_record_name
  type            = each.value.resource_record_type
  records         = [each.value.resource_record_value]
  ttl             = 300
  allow_overwrite = true
}

resource "aws_acm_certificate_validation" "this" {
  certificate_arn         = aws_acm_certificate.this.arn
  validation_record_fqdns = [for r in aws_route53_record.validation : r.fqdn]
}

module "alb_waf" {
  source              = "../modules/alb_waf"
  name                = local.name
  vpc_id              = module.vpc.vpc_id
  vpc_cidr            = module.vpc.vpc_cidr
  public_subnet_ids   = module.vpc.public_subnet_ids
  certificate_arn     = aws_acm_certificate_validation.this.certificate_arn
  allowed_cidrs       = var.alb_allowed_cidrs
  rate_limit_per_5min = var.waf_rate_limit_per_5min
  log_bucket          = module.logs_bucket.bucket
  logs_kms_key_arn    = module.kms.key_arns["logs"]
  log_retention_days  = var.log_retention_days
  deletion_protection = var.deletion_protection
  tags                = local.tags
}

# ingress-nginx pods (VPC CNI: pod IPs carry the cluster security group) accept 443 from the ALB only.
resource "aws_vpc_security_group_ingress_rule" "alb_to_ingress" {
  security_group_id            = module.eks.cluster_security_group_id
  description                  = "ALB to ingress-nginx"
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  referenced_security_group_id = module.alb_waf.alb_security_group_id
}

resource "aws_route53_record" "app" {
  zone_id = data.aws_route53_zone.public.zone_id
  name    = var.domain_name
  type    = "A"

  alias {
    name                   = module.alb_waf.alb_dns_name
    zone_id                = module.alb_waf.alb_zone_id
    evaluate_target_health = true
  }
}

# ---------------------------------------------------------------- backups and monitoring
module "backup" {
  source         = "../modules/backup"
  providers      = { aws = aws, aws.dr = aws.dr }
  name           = local.name
  kms_key_arn    = module.kms.key_arns["backup"]
  dr_kms_key_arn = module.kms_dr.key_arns["backup"]
  rds_arn        = module.rds.instance_arn
  efs_arn        = module.efs.file_system_arn
  s3_bucket_arns = [module.evidence_bucket.arn, module.backup_bucket.arn]
  tags           = local.tags
}

module "cloudwatch" {
  source              = "../modules/cloudwatch"
  name                = local.name
  kms_key_arn         = module.kms.key_arns["logs"]
  log_retention_days  = var.log_retention_days
  alarm_emails        = var.alarm_emails
  rds_instance_id     = module.rds.instance_id
  alb_arn_suffix      = module.alb_waf.alb_arn_suffix
  waf_web_acl_name    = module.alb_waf.web_acl_name
  efs_file_system_id  = module.efs.file_system_id
  evidence_bucket     = module.evidence_bucket.bucket
  replication_enabled = var.enable_replication
  replica_bucket      = var.enable_replication ? "${local.name}-evidence-${local.account}-replica" : ""
  backup_vault_name   = module.backup.vault_name
  tags                = local.tags
}

# ---------------------------------------------------------------- in-cluster resources
resource "kubernetes_namespace_v1" "veritas" {
  metadata {
    name = var.namespace
    labels = {
      "pod-security.kubernetes.io/enforce" = "restricted"
      "pod-security.kubernetes.io/audit"   = "restricted"
      "veritas.io/clickhouse-client"       = "true"
    }
  }
  depends_on = [module.eks]
}

resource "kubernetes_storage_class_v1" "efs" {
  metadata {
    name = "efs-sc"
  }
  storage_provisioner = "efs.csi.aws.com"
  reclaim_policy      = "Retain"
  parameters = {
    provisioningMode = "efs-ap"
    fileSystemId     = module.efs.file_system_id
    directoryPerms   = "750"
    uid              = "10001"
    gid              = "10001"
    basePath         = "/veritas-dynamic"
  }
  depends_on = [module.eks]
}

module "clickhouse" {
  source              = "../modules/clickhouse"
  replicas            = var.clickhouse_replicas
  ebs_kms_key_arn     = module.kms.key_arns["eks"]
  irsa_role_arn       = module.irsa.role_arns["clickhouse"]
  secret_name         = "veritas/${var.environment}/clickhouse"
  secrets_kms_key_arn = module.kms.key_arns["secrets"]
  tags                = local.tags
  depends_on          = [module.eks]
}

# ---------------------------------------------------------------- optional OpenSearch
data "aws_iam_policy_document" "opensearch_admin_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${local.part}:iam::${local.account}:root"]
    }
    condition {
      test     = "Bool"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["true"]
    }
  }
}

resource "aws_iam_role" "opensearch_admin" {
  count = var.enable_opensearch ? 1 : 0

  name               = "${local.name}-opensearch-admin"
  assume_role_policy = data.aws_iam_policy_document.opensearch_admin_assume.json
  tags               = local.tags
}

module "opensearch" {
  source                     = "../modules/opensearch"
  count                      = var.enable_opensearch ? 1 : 0
  name                       = "${local.name}-search"
  vpc_id                     = module.vpc.vpc_id
  subnet_ids                 = module.vpc.private_subnet_ids
  allowed_security_group_ids = [module.eks.cluster_security_group_id]
  kms_key_arn                = module.kms.key_arns["opensearch"]
  logs_kms_key_arn           = module.kms.key_arns["logs"]
  master_role_arn            = aws_iam_role.opensearch_admin[0].arn
  tags                       = local.tags
}
