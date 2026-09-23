data "kubernetes_namespace" "auth_api" {
  metadata {
    name = var.namespace
  }
}

data "terraform_remote_state" "cluster_config" {
  backend = "local"

  config = {
    path = "${path.module}/../../cluster-config/tofu/terraform.tfstate"
  }
}

locals {
  instance_name = "auth-api"

  registry_host = split("/", var.image_repository)[0]
  registry_repo = join("/", slice(split("/", var.image_repository), 1, length(split("/", var.image_repository))))
  issuer_url    = "https://${var.issuer_hostname}"
}

data "external" "auth_api_latest_tag" {
  program = ["python3", "${path.module}/scripts/latest_image_tag.py"]

  query = {
    registry_host = local.registry_host
    repo          = local.registry_repo
    prefix        = var.image_tag_prefix
    username      = data.terraform_remote_state.cluster_config.outputs.clusterkeep_ui_registry_username
    password      = data.terraform_remote_state.cluster_config.outputs.clusterkeep_ui_registry_password
  }
}

locals {
  deployed_image_tag = (
    var.image_tag_prefix != "" && data.external.auth_api_latest_tag.result.tag != ""
    ? data.external.auth_api_latest_tag.result.tag
    : var.image_tag
  )
}

resource "random_password" "password_pepper" {
  length  = 64
  special = false
}

resource "random_password" "bootstrap_password" {
  length  = 24
  special = false
}

# Kept out of helm_release.values - that attribute isn't sensitive and renders in full in plan output.
resource "kubernetes_secret" "auth_api" {
  metadata {
    name      = "${local.instance_name}-secrets"
    namespace = data.kubernetes_namespace.auth_api.metadata[0].name
  }

  data = {
    AUTH_API_DATABASE_URL = format(
      "postgresql+asyncpg://auth_api:%s@%s.%s.svc.cluster.local:5432/auth_api",
      random_password.postgres.result,
      kubernetes_service.postgres.metadata[0].name,
      data.kubernetes_namespace.auth_api.metadata[0].name,
    )
    AUTH_API_PASSWORD_PEPPER    = random_password.password_pepper.result
    AUTH_API_REGISTRATION_TOKEN = var.registration_token
    AUTH_API_BOOTSTRAP_USERNAME = var.bootstrap_username
    AUTH_API_BOOTSTRAP_PASSWORD = random_password.bootstrap_password.result
    AUTH_API_BOOTSTRAP_EMAIL    = var.bootstrap_email
  }
}

resource "helm_release" "auth_api" {
  name      = local.instance_name
  chart     = "${path.module}/../../charts/auth-api"
  namespace = data.kubernetes_namespace.auth_api.metadata[0].name

  atomic = true

  values = [
    yamlencode({
      replicaCount = var.replica_count
      image = {
        repository = var.image_repository
        tag        = local.deployed_image_tag
      }
      ingress = {
        enabled       = var.ingress_enabled
        host          = var.issuer_hostname
        tls           = true
        tlsSecretName = var.ingress_tls_secret_name
      }
      config = {
        environment          = var.environment
        issuerUrl            = local.issuer_url
        cookieDomain         = var.cookie_domain
        cookieSecure         = true
        redisNamespace       = "authapi"
        headlampUrl          = var.headlamp_url
        allowedRedirectHosts = var.allowed_redirect_hosts
        defaultRedirectUrl   = var.default_redirect_url
      }
      redis = {
        host     = kubernetes_service.redis.metadata[0].name
        port     = 6379
        database = 0
      }
      existingSecret        = kubernetes_secret.auth_api.metadata[0].name
      clusterIdentitySecret = var.cluster_identity_secret_name
      imagePullSecrets = var.image_pull_secret_name != "" ? [
        { name = var.image_pull_secret_name }
      ] : []
    })
  ]

  depends_on = [
    kubernetes_stateful_set_v1.postgres,
    kubernetes_deployment_v1.redis,
  ]
}
