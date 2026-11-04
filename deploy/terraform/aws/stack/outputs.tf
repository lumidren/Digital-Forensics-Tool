output "cluster_name" {
  description = "EKS cluster name (aws eks update-kubeconfig --name ...)."
  value       = module.eks.cluster_name
}

output "cluster_endpoint" {
  description = "EKS API endpoint."
  value       = module.eks.cluster_endpoint
}

output "cluster_ca" {
  description = "EKS cluster CA (base64)."
  value       = module.eks.cluster_ca
}

output "evidence_bucket" {
  description = "Helm config.s3Bucket."
  value       = module.evidence_bucket.bucket
}

output "backup_bucket" {
  description = "Helm backup.uploadUrl bucket (prefix app/)."
  value       = module.backup_bucket.bucket
}

output "irsa_role_arns" {
  description = "Helm serviceAccounts.{api,worker,ops}.roleArn."
  value       = module.irsa.role_arns
}

output "postgres_endpoint" {
  description = "RDS writer endpoint (host:port) for VERITAS_DATABASE_URL."
  value       = module.rds.endpoint
}

output "postgres_master_secret_arn" {
  description = "Secrets Manager secret with the RDS master credentials."
  value       = module.rds.master_user_secret_arn
}

output "database_subnet_cidrs" {
  description = "Helm networkPolicy.postgresCidrs."
  value       = module.vpc.database_subnet_cidrs
}

output "vpc_cidr" {
  description = "Helm networkPolicy.awsEndpointCidrs."
  value       = module.vpc.vpc_cidr
}

output "efs_file_system_id" {
  description = "Shared data directory file system."
  value       = module.efs.file_system_id
}

output "alb_target_group_arn" {
  description = "TargetGroupBinding target for the ingress-nginx Service."
  value       = module.alb_waf.target_group_arn
}

output "alb_dns_name" {
  description = "ALB DNS name."
  value       = module.alb_waf.alb_dns_name
}

output "runtime_secret_name" {
  description = "Secrets Manager secret read by External Secrets (Helm externalSecrets.remoteKey)."
  value       = aws_secretsmanager_secret.runtime.name
}

output "clickhouse_secret_arn" {
  description = "ClickHouse credentials (source of VERITAS_TIMELINE_URL)."
  value       = module.clickhouse.secret_arn
}

output "alarm_topic_arn" {
  description = "SNS topic for CloudWatch alarms."
  value       = module.cloudwatch.sns_topic_arn
}

output "backup_dr_vault_arn" {
  description = "AWS Backup vault in the DR region."
  value       = module.backup.dr_vault_arn
}

output "opensearch_endpoint" {
  description = "OpenSearch endpoint (null unless enable_opensearch)."
  value       = var.enable_opensearch ? module.opensearch[0].endpoint : null
}
