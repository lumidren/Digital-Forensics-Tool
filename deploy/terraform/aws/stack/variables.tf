variable "environment" {
  description = "Environment name (staging, prod)."
  type        = string
}

variable "vpc_cidr" {
  description = "VPC CIDR (/16)."
  type        = string
}

variable "azs" {
  description = "Three Availability Zones in the primary region."
  type        = list(string)
}

variable "single_nat_gateway" {
  description = "Share one NAT gateway across AZs (non-production)."
  type        = bool
  default     = false
}

variable "kubernetes_version" {
  description = "EKS version."
  type        = string
  default     = "1.31"
}

variable "eks_public_access_cidrs" {
  description = "CIDRs allowed to the public EKS endpoint (empty: private endpoint only)."
  type        = list(string)
  default     = []
}

variable "eks_admin_role_arns" {
  description = "IAM roles with cluster-admin (CI deploy role, break-glass role)."
  type        = list(string)
  default     = []
}

variable "system_node_scaling" {
  description = "System node group min/desired/max."
  type        = object({ min = number, desired = number, max = number })
}

variable "worker_node_scaling" {
  description = "Worker node group min/desired/max."
  type        = object({ min = number, desired = number, max = number })
}

variable "worker_instance_types" {
  description = "Worker node instance types."
  type        = list(string)
  default     = ["c6i.4xlarge"]
}

variable "rds_instance_class" {
  description = "RDS instance class."
  type        = string
}

variable "evidence_retention_days" {
  description = "Default Object Lock COMPLIANCE retention for evidence."
  type        = number
}

variable "backup_archive_retention_days" {
  description = "Default Object Lock COMPLIANCE retention for application backup archives."
  type        = number
  default     = 90
}

variable "enable_replication" {
  description = "Replicate evidence and backup archives to the DR region."
  type        = bool
  default     = true
}

variable "domain_name" {
  description = "Public host name of the Veritas web UI and API."
  type        = string
}

variable "route53_zone_name" {
  description = "Route 53 public hosted zone containing domain_name."
  type        = string
}

variable "alb_allowed_cidrs" {
  description = "Client CIDRs allowed to reach the ALB."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "waf_rate_limit_per_5min" {
  description = "WAF per-IP request limit per 5 minutes."
  type        = number
  default     = 2000
}

variable "alarm_emails" {
  description = "E-mail recipients of CloudWatch alarms."
  type        = list(string)
  default     = []
}

variable "log_retention_days" {
  description = "Retention of CloudWatch log groups."
  type        = number
  default     = 365
}

variable "enable_opensearch" {
  description = "Also create an Amazon OpenSearch domain (timeline search uses ClickHouse regardless)."
  type        = bool
  default     = false
}

variable "clickhouse_replicas" {
  description = "ClickHouse replicas."
  type        = number
  default     = 3
}

variable "deletion_protection" {
  description = "Deletion protection on RDS and the ALB."
  type        = bool
  default     = true
}

variable "namespace" {
  description = "Kubernetes namespace of the Veritas release."
  type        = string
  default     = "veritas"
}

variable "tags" {
  description = "Extra tags."
  type        = map(string)
  default     = {}
}
