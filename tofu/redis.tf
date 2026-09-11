resource "kubernetes_service" "redis" {
  metadata {
    name      = "${local.instance_name}-redis"
    namespace = data.kubernetes_namespace.auth_api.metadata[0].name
  }

  spec {
    selector = {
      app = "${local.instance_name}-redis"
    }
    port {
      port        = 6379
      target_port = 6379
    }
  }
}

# Deliberately has no PersistentVolume - session data is reconstructible by logging in again.
resource "kubernetes_deployment_v1" "redis" {
  metadata {
    name      = "${local.instance_name}-redis"
    namespace = data.kubernetes_namespace.auth_api.metadata[0].name
  }

  spec {
    replicas = 1

    selector {
      match_labels = {
        app = "${local.instance_name}-redis"
      }
    }

    template {
      metadata {
        labels = {
          app = "${local.instance_name}-redis"
        }
      }

      spec {
        security_context {
          run_as_non_root = true
          run_as_user     = 999
          fs_group        = 999
        }

        container {
          name  = "redis"
          image = var.redis_image

          args = [
            "--save", "",
            "--appendonly", "no",
            "--maxmemory", var.redis_max_memory,
            # noeviction - a full cache should refuse writes rather than evict a live session mid-request.
            "--maxmemory-policy", "noeviction",
          ]

          port {
            container_port = 6379
          }

          security_context {
            allow_privilege_escalation = false
            read_only_root_filesystem  = true
            capabilities {
              drop = ["ALL"]
            }
          }

          resources {
            requests = {
              cpu    = "50m"
              memory = "64Mi"
            }
            limits = {
              cpu    = "300m"
              memory = "320Mi"
            }
          }

          readiness_probe {
            exec {
              command = ["redis-cli", "ping"]
            }
            period_seconds    = 5
            timeout_seconds   = 3
            failure_threshold = 3
          }

          liveness_probe {
            tcp_socket {
              port = 6379
            }
            period_seconds    = 20
            failure_threshold = 6
          }
        }
      }
    }
  }
}
