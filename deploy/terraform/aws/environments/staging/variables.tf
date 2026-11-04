variable "region" {
  description = "Primary AWS region."
  type        = string
  default     = "eu-west-1"
}

variable "dr_region" {
  description = "Disaster-recovery AWS region."
  type        = string
  default     = "eu-central-1"
}

variable "domain_name" {
  description = "Public host name, e.g. staging.veritas.<your-domain>."
  type        = string
}

variable "route53_zone_name" {
  description = "Route 53 public hosted zone that contains domain_name."
  type        = string
}

variable "eks_public_access_cidrs" {
  description = "Admin CIDRs for the public EKS endpoint; empty keeps the endpoint private."
  type        = list(string)
  default     = []
}

variable "eks_admin_role_arns" {
  description = "IAM roles with cluster-admin (GitHub OIDC deploy role, break-glass)."
  type        = list(string)
  default     = []
}

variable "alarm_emails" {
  description = "CloudWatch alarm recipients."
  type        = list(string)
  default     = []
}

variable "enable_opensearch" {
  description = "Create the optional Amazon OpenSearch domain."
  type        = bool
  default     = false
}
