# EKS cluster: KMS envelope encryption of Secrets, all control-plane log types, IRSA (OIDC provider),
# a system node group and a tainted worker node group for evidence processing, IMDSv2-only nodes with
# KMS-encrypted root volumes, and the EBS/EFS CSI drivers with their own IRSA roles.

variable "name" {
  description = "Cluster name."
  type        = string
}

variable "kubernetes_version" {
  description = "EKS Kubernetes version."
  type        = string
  default     = "1.31"
}

variable "vpc_id" {
  description = "VPC ID."
  type        = string
}

variable "subnet_ids" {
  description = "Private subnets for the control plane ENIs and the nodes."
  type        = list(string)
}

variable "public_access_cidrs" {
  description = "CIDRs allowed to reach the public API endpoint; empty disables the public endpoint."
  type        = list(string)
  default     = []
}

variable "secrets_kms_key_arn" {
  description = "KMS key for Secrets envelope encryption and node volumes."
  type        = string
}

variable "logs_kms_key_arn" {
  description = "KMS key for the control-plane log group."
  type        = string
}

variable "log_retention_days" {
  description = "Control-plane log retention."
  type        = number
  default     = 365
}

variable "system_instance_types" {
  description = "Instance types for the system node group."
  type        = list(string)
  default     = ["m6i.xlarge"]
}

variable "system_scaling" {
  description = "min/desired/max for the system node group."
  type        = object({ min = number, desired = number, max = number })
  default     = { min = 3, desired = 3, max = 6 }
}

variable "worker_instance_types" {
  description = "Instance types for the evidence-processing node group."
  type        = list(string)
  default     = ["c6i.4xlarge"]
}

variable "worker_scaling" {
  description = "min/desired/max for the worker node group."
  type        = object({ min = number, desired = number, max = number })
  default     = { min = 1, desired = 1, max = 4 }
}

variable "worker_volume_size_gb" {
  description = "Root volume of worker nodes (holds emptyDir scratch for materialized evidence)."
  type        = number
  default     = 1000
}

variable "admin_role_arns" {
  description = "IAM roles granted cluster-admin through EKS access entries (e.g. the deploy role used by CI)."
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Tags for every resource."
  type        = map(string)
  default     = {}
}

data "aws_partition" "current" {}

locals {
  part = data.aws_partition.current.partition
}

# ---------------------------------------------------------------- control plane
data "aws_iam_policy_document" "cluster_assume" {
  statement {
    actions = ["sts:AssumeRole", "sts:TagSession"]
    principals {
      type        = "Service"
      identifiers = ["eks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "cluster" {
  name               = "${var.name}-cluster"
  assume_role_policy = data.aws_iam_policy_document.cluster_assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "cluster" {
  role       = aws_iam_role.cluster.name
  policy_arn = "arn:${local.part}:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_cloudwatch_log_group" "cluster" {
  name              = "/aws/eks/${var.name}/cluster"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.logs_kms_key_arn
  tags              = var.tags
}

resource "aws_security_group" "cluster" {
  name        = "${var.name}-cluster"
  description = "EKS control plane additional security group"
  vpc_id      = var.vpc_id
  tags        = merge(var.tags, { Name = "${var.name}-cluster" })
}

resource "aws_eks_cluster" "this" {
  name                      = var.name
  version                   = var.kubernetes_version
  role_arn                  = aws_iam_role.cluster.arn
  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  vpc_config {
    subnet_ids              = var.subnet_ids
    security_group_ids      = [aws_security_group.cluster.id]
    endpoint_private_access = true
    endpoint_public_access  = length(var.public_access_cidrs) > 0
    public_access_cidrs     = length(var.public_access_cidrs) > 0 ? var.public_access_cidrs : null
  }

  encryption_config {
    resources = ["secrets"]
    provider {
      key_arn = var.secrets_kms_key_arn
    }
  }

  access_config {
    authentication_mode                         = "API"
    bootstrap_cluster_creator_admin_permissions = true
  }

  tags = var.tags

  depends_on = [aws_iam_role_policy_attachment.cluster, aws_cloudwatch_log_group.cluster]
}

resource "aws_eks_access_entry" "admin" {
  for_each = toset(var.admin_role_arns)

  cluster_name  = aws_eks_cluster.this.name
  principal_arn = each.value
  type          = "STANDARD"
  tags          = var.tags
}

resource "aws_eks_access_policy_association" "admin" {
  for_each = toset(var.admin_role_arns)

  cluster_name  = aws_eks_cluster.this.name
  principal_arn = each.value
  policy_arn    = "arn:${local.part}:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
  access_scope {
    type = "cluster"
  }

  depends_on = [aws_eks_access_entry.admin]
}

# ---------------------------------------------------------------- IRSA
data "tls_certificate" "oidc" {
  url = aws_eks_cluster.this.identity[0].oidc[0].issuer
}

resource "aws_iam_openid_connect_provider" "this" {
  url             = aws_eks_cluster.this.identity[0].oidc[0].issuer
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.oidc.certificates[0].sha1_fingerprint]
  tags            = var.tags
}

locals {
  oidc_host = replace(aws_iam_openid_connect_provider.this.url, "https://", "")
}

# ---------------------------------------------------------------- nodes
data "aws_iam_policy_document" "node_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "node" {
  name               = "${var.name}-node"
  assume_role_policy = data.aws_iam_policy_document.node_assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "node" {
  for_each = toset([
    "AmazonEKSWorkerNodePolicy",
    "AmazonEKS_CNI_Policy",
    "AmazonEC2ContainerRegistryReadOnly",
    "AmazonSSMManagedInstanceCore",
  ])

  role       = aws_iam_role.node.name
  policy_arn = "arn:${local.part}:iam::aws:policy/${each.value}"
}

resource "aws_launch_template" "node" {
  for_each = {
    system  = 100
    workers = var.worker_volume_size_gb
  }

  name_prefix            = "${var.name}-${each.key}-"
  update_default_version = true

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size           = each.value
      volume_type           = "gp3"
      encrypted             = true
      kms_key_id            = var.secrets_kms_key_arn
      delete_on_termination = true
    }
  }

  monitoring {
    enabled = true
  }

  tag_specifications {
    resource_type = "instance"
    tags          = merge(var.tags, { Name = "${var.name}-${each.key}" })
  }

  tags = var.tags
}

resource "aws_eks_node_group" "system" {
  cluster_name    = aws_eks_cluster.this.name
  node_group_name = "system"
  node_role_arn   = aws_iam_role.node.arn
  subnet_ids      = var.subnet_ids
  instance_types  = var.system_instance_types
  capacity_type   = "ON_DEMAND"
  ami_type        = "AL2023_x86_64_STANDARD"

  scaling_config {
    min_size     = var.system_scaling.min
    desired_size = var.system_scaling.desired
    max_size     = var.system_scaling.max
  }

  update_config {
    max_unavailable = 1
  }

  launch_template {
    id      = aws_launch_template.node["system"].id
    version = aws_launch_template.node["system"].latest_version
  }

  labels = {
    "veritas.io/pool" = "system"
  }

  tags       = var.tags
  depends_on = [aws_iam_role_policy_attachment.node]

  lifecycle {
    ignore_changes = [scaling_config[0].desired_size]
  }
}

resource "aws_eks_node_group" "workers" {
  cluster_name    = aws_eks_cluster.this.name
  node_group_name = "workers"
  node_role_arn   = aws_iam_role.node.arn
  subnet_ids      = var.subnet_ids
  instance_types  = var.worker_instance_types
  capacity_type   = "ON_DEMAND"
  ami_type        = "AL2023_x86_64_STANDARD"

  scaling_config {
    min_size     = var.worker_scaling.min
    desired_size = var.worker_scaling.desired
    max_size     = var.worker_scaling.max
  }

  update_config {
    max_unavailable = 1
  }

  launch_template {
    id      = aws_launch_template.node["workers"].id
    version = aws_launch_template.node["workers"].latest_version
  }

  labels = {
    "veritas.io/pool" = "workers"
  }

  # Only evidence-processing pods (which tolerate this taint) are scheduled here.
  taint {
    key    = "veritas.io/pool"
    value  = "workers"
    effect = "NO_SCHEDULE"
  }

  tags       = var.tags
  depends_on = [aws_iam_role_policy_attachment.node]

  lifecycle {
    ignore_changes = [scaling_config[0].desired_size]
  }
}

# ---------------------------------------------------------------- add-ons
data "aws_iam_policy_document" "csi_assume" {
  for_each = {
    ebs = "system:serviceaccount:kube-system:ebs-csi-controller-sa"
    efs = "system:serviceaccount:kube-system:efs-csi-controller-sa"
  }

  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.this.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:sub"
      values   = [each.value]
    }
    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "csi" {
  for_each = data.aws_iam_policy_document.csi_assume

  name               = "${var.name}-${each.key}-csi"
  assume_role_policy = each.value.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "csi" {
  for_each = {
    ebs = "arn:${local.part}:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
    efs = "arn:${local.part}:iam::aws:policy/service-role/AmazonEFSCSIDriverPolicy"
  }

  role       = aws_iam_role.csi[each.key].name
  policy_arn = each.value
}

data "aws_iam_policy_document" "ebs_csi_kms" {
  statement {
    actions   = ["kms:CreateGrant", "kms:ListGrants", "kms:RevokeGrant"]
    resources = [var.secrets_kms_key_arn]
    condition {
      test     = "Bool"
      variable = "kms:GrantIsForAWSResource"
      values   = ["true"]
    }
  }
  statement {
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey"]
    resources = [var.secrets_kms_key_arn]
  }
}

resource "aws_iam_role_policy" "ebs_csi_kms" {
  name   = "kms"
  role   = aws_iam_role.csi["ebs"].id
  policy = data.aws_iam_policy_document.ebs_csi_kms.json
}

resource "aws_eks_addon" "this" {
  for_each = {
    vpc-cni                = null
    coredns                = null
    kube-proxy             = null
    aws-ebs-csi-driver     = aws_iam_role.csi["ebs"].arn
    aws-efs-csi-driver     = aws_iam_role.csi["efs"].arn
    eks-pod-identity-agent = null
  }

  cluster_name                = aws_eks_cluster.this.name
  addon_name                  = each.key
  service_account_role_arn    = each.value
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "PRESERVE"
  configuration_values        = each.key == "vpc-cni" ? jsonencode({ enableNetworkPolicy = "true" }) : null
  tags                        = var.tags

  depends_on = [aws_eks_node_group.system]
}

output "cluster_name" {
  description = "Cluster name."
  value       = aws_eks_cluster.this.name
}

output "cluster_endpoint" {
  description = "API server endpoint."
  value       = aws_eks_cluster.this.endpoint
}

output "cluster_ca" {
  description = "Base64 cluster CA certificate."
  value       = aws_eks_cluster.this.certificate_authority[0].data
}

output "cluster_security_group_id" {
  description = "EKS-managed cluster security group (attached to managed nodes and pods)."
  value       = aws_eks_cluster.this.vpc_config[0].cluster_security_group_id
}

output "oidc_provider_arn" {
  description = "IRSA OIDC provider ARN."
  value       = aws_iam_openid_connect_provider.this.arn
}

output "oidc_provider_host" {
  description = "IRSA OIDC issuer host (without https://)."
  value       = local.oidc_host
}
