# Veritas staging environment.
#   terraform init -backend-config=backend.hcl
#   terraform plan -var domain_name=... -var route53_zone_name=... -out staging.tfplan
# First apply on an empty account: create the cluster before in-cluster resources, because the
# helm/kubernetes providers read the cluster endpoint from module outputs:
#   terraform apply -target=module.stack.module.eks -var ... && terraform apply -var ...

provider "aws" {
  region = var.region
  default_tags {
    tags = {
      Application = "veritas"
      Environment = "staging"
    }
  }
}

provider "aws" {
  alias  = "dr"
  region = var.dr_region
  default_tags {
    tags = {
      Application = "veritas"
      Environment = "staging"
      Role        = "disaster-recovery"
    }
  }
}

provider "kubernetes" {
  host                   = module.stack.cluster_endpoint
  cluster_ca_certificate = base64decode(module.stack.cluster_ca)
  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", module.stack.cluster_name, "--region", var.region]
  }
}

provider "helm" {
  kubernetes {
    host                   = module.stack.cluster_endpoint
    cluster_ca_certificate = base64decode(module.stack.cluster_ca)
    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args        = ["eks", "get-token", "--cluster-name", module.stack.cluster_name, "--region", var.region]
    }
  }
}

module "stack" {
  source    = "../../stack"
  providers = { aws = aws, aws.dr = aws.dr, helm = helm, kubernetes = kubernetes }

  environment             = "staging"
  vpc_cidr                = "10.20.0.0/16"
  azs                     = ["eu-west-1a", "eu-west-1b", "eu-west-1c"]
  single_nat_gateway      = true
  eks_public_access_cidrs = var.eks_public_access_cidrs
  eks_admin_role_arns     = var.eks_admin_role_arns
  system_node_scaling     = { min = 2, desired = 2, max = 4 }
  worker_node_scaling     = { min = 1, desired = 1, max = 2 }
  worker_instance_types   = ["c6i.2xlarge"]
  rds_instance_class      = "db.t4g.large"
  evidence_retention_days = 365
  enable_replication      = true
  clickhouse_replicas     = 2
  deletion_protection     = false
  waf_rate_limit_per_5min = 2000
  domain_name             = var.domain_name
  route53_zone_name       = var.route53_zone_name
  alarm_emails            = var.alarm_emails
  enable_opensearch       = var.enable_opensearch
}
