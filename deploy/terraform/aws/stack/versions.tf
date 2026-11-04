terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source                = "hashicorp/aws"
      version               = ">= 5.70.0, < 6.0.0"
      configuration_aliases = [aws.dr]
    }
    helm = {
      source  = "hashicorp/helm"
      version = ">= 2.15.0, < 3.0.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.32.0, < 3.0.0"
    }
  }
}
