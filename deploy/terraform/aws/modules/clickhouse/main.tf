# Timeline index for the cluster profile: ClickHouse on EKS (Bitnami chart) with ClickHouse Keeper,
# replicated across AZs on encrypted gp3 volumes, credentials generated here and stored in Secrets
# Manager (KMS), the service account bound to the IRSA role that may write BACKUP files to S3.

variable "namespace" {
  description = "Namespace for ClickHouse."
  type        = string
  default     = "clickhouse"
}

variable "chart_version" {
  description = "Bitnami ClickHouse chart version."
  type        = string
  default     = "6.2.27"
}

variable "replicas" {
  description = "ClickHouse replicas (one shard)."
  type        = number
  default     = 3
}

variable "storage_size" {
  description = "Persistent volume size per replica."
  type        = string
  default     = "500Gi"
}

variable "ebs_kms_key_arn" {
  description = "KMS key for the gp3 StorageClass."
  type        = string
}

variable "service_account_name" {
  description = "Service account name (IRSA)."
  type        = string
  default     = "clickhouse"
}

variable "irsa_role_arn" {
  description = "IRSA role allowed to write backups."
  type        = string
}

variable "secret_name" {
  description = "Secrets Manager secret receiving the ClickHouse credentials."
  type        = string
}

variable "secrets_kms_key_arn" {
  description = "KMS key for the Secrets Manager secret."
  type        = string
}

variable "resources" {
  description = "Container resources per replica."
  type = object({
    requests = map(string)
    limits   = map(string)
  })
  default = {
    requests = { cpu = "2", memory = "8Gi" }
    limits   = { cpu = "4", memory = "16Gi" }
  }
}

variable "tags" {
  description = "Tags for AWS resources."
  type        = map(string)
  default     = {}
}

resource "kubernetes_namespace_v1" "this" {
  metadata {
    name = var.namespace
    labels = {
      "pod-security.kubernetes.io/enforce" = "restricted"
    }
  }
}

resource "kubernetes_storage_class_v1" "gp3" {
  metadata {
    name = "gp3-encrypted"
  }
  storage_provisioner    = "ebs.csi.aws.com"
  reclaim_policy         = "Retain"
  volume_binding_mode    = "WaitForFirstConsumer"
  allow_volume_expansion = true
  parameters = {
    type      = "gp3"
    encrypted = "true"
    kmsKeyId  = var.ebs_kms_key_arn
  }
}

resource "random_password" "clickhouse" {
  length  = 40
  special = false
}

resource "aws_secretsmanager_secret" "clickhouse" {
  name       = var.secret_name
  kms_key_id = var.secrets_kms_key_arn
  tags       = var.tags
}

resource "aws_secretsmanager_secret_version" "clickhouse" {
  secret_id = aws_secretsmanager_secret.clickhouse.id
  secret_string = jsonencode({
    username = "veritas"
    password = random_password.clickhouse.result
    url      = "clickhouse://veritas:${random_password.clickhouse.result}@clickhouse.${var.namespace}.svc:8123/veritas"
  })
}

resource "kubernetes_secret_v1" "auth" {
  metadata {
    name      = "clickhouse-auth"
    namespace = kubernetes_namespace_v1.this.metadata[0].name
  }
  data = {
    admin-password = random_password.clickhouse.result
  }
}

resource "helm_release" "clickhouse" {
  name       = "clickhouse"
  namespace  = kubernetes_namespace_v1.this.metadata[0].name
  repository = "oci://registry-1.docker.io/bitnamicharts"
  chart      = "clickhouse"
  version    = var.chart_version
  atomic     = true
  timeout    = 900

  values = [yamlencode({
    shards       = 1
    replicaCount = var.replicas
    auth = {
      username          = "veritas"
      existingSecret    = kubernetes_secret_v1.auth.metadata[0].name
      existingSecretKey = "admin-password"
    }
    keeper    = { enabled = true }
    zookeeper = { enabled = false }
    persistence = {
      enabled      = true
      storageClass = kubernetes_storage_class_v1.gp3.metadata[0].name
      size         = var.storage_size
    }
    resources = var.resources
    serviceAccount = {
      create = true
      name   = var.service_account_name
      annotations = {
        "eks.amazonaws.com/role-arn" = var.irsa_role_arn
      }
    }
    podSecurityContext = {
      enabled        = true
      fsGroup        = 1001
      seccompProfile = { type = "RuntimeDefault" }
    }
    containerSecurityContext = {
      enabled                  = true
      runAsNonRoot             = true
      runAsUser                = 1001
      allowPrivilegeEscalation = false
      readOnlyRootFilesystem   = true
      capabilities             = { drop = ["ALL"] }
      seccompProfile           = { type = "RuntimeDefault" }
    }
    topologySpreadConstraints = [{
      maxSkew           = 1
      topologyKey       = "topology.kubernetes.io/zone"
      whenUnsatisfiable = "DoNotSchedule"
      labelSelector     = { matchLabels = { "app.kubernetes.io/name" = "clickhouse", "app.kubernetes.io/component" = "clickhouse" } }
    }]
    nodeSelector = { "veritas.io/pool" = "system" }
    networkPolicy = {
      enabled       = true
      allowExternal = false
      extraIngress = [{
        from  = [{ namespaceSelector = { matchLabels = { "veritas.io/clickhouse-client" = "true" } } }]
        ports = [{ port = 8123, protocol = "TCP" }]
      }]
    }
    defaultConfigurationOverrides = <<-XML
      <clickhouse>
        <backups>
          <allowed_path>/bitnami/clickhouse/backups/</allowed_path>
        </backups>
        <s3>
          <use_environment_credentials>true</use_environment_credentials>
        </s3>
      </clickhouse>
    XML
  })]
}

output "secret_arn" {
  description = "Secrets Manager secret with the ClickHouse URL used for VERITAS_TIMELINE_URL."
  value       = aws_secretsmanager_secret.clickhouse.arn
}

output "namespace" {
  description = "ClickHouse namespace."
  value       = kubernetes_namespace_v1.this.metadata[0].name
}
