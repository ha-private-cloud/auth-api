output "issuer_url" {
  description = "OIDC issuer URL. Goes into Headlamp's config.oidc.issuerURL and, on cutover, the apiserver's oidc-issuer-url."
  value       = local.issuer_url
}

output "discovery_url" {
  description = "OIDC discovery document, for checking the deployment answers before pointing anything at it."
  value       = "${local.issuer_url}/.well-known/openid-configuration"
}

output "pq_jwks_url" {
  description = "ML-DSA-65 public key, for services verifying auth-api's service tokens offline."
  value       = "${local.issuer_url}/pq/jwks.json"
}

output "headlamp_oidc_client_id" {
  description = "Client ID auth-api registers for Headlamp on startup."
  value       = "headlamp"
}

output "headlamp_oidc_client_secret" {
  description = "Client secret for Headlamp's OIDC config in cluster-config, replacing the Authentik one."
  value       = random_password.headlamp_client_secret.result
  sensitive   = true
}

output "headlamp_oidc_issuer_url" {
  description = "Drop-in replacement for cluster-auth's output of the same name."
  value       = local.issuer_url
}

output "bootstrap_username" {
  description = "Admin account created on first start."
  value       = var.bootstrap_username
}

output "bootstrap_password" {
  description = "Generated password for the bootstrap admin. The account is flagged must_change_password."
  value       = random_password.bootstrap_password.result
  sensitive   = true
}
