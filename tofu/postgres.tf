resource "random_password" "postgres" {
  length  = 32
  special = false
}

resource "kubernetes_secret" "postgres" {
  metadata {
    name      = "${local.instance_name}-postgres"
    namespace = data.kubernetes_namespace.auth_api.metadata[0].name
  }

  data = {
    POSTGRES_USER     = "auth_api"
    POSTGRES_PASSWORD = random_password.postgres.result
    POSTGRES_DB       = "auth_api"
  }
}

resource "kubernetes_service" "postgres" {
  metadata {
    name      = "${local.instance_name}-postgres"
    namespace = data.kubernetes_namespace.auth_api.metadata[0].name
  }

  spec {
    cluster_ip = "None"
    selector = {
      app = "${local.instance_name}-postgres"
    }
    port {
      port        = 5432
      target_port = 5432
    }
  }
}

resource "kubernetes_stateful_set_v1" "postgres" {
  metadata {
    name      = "${local.instance_name}-postgres"
    namespace = data.kubernetes_namespace.auth_api.metadata[0].name
  }

  spec {
    service_name = kubernetes_service.postgres.metadata[0].name
    replicas     = 1

    selector {
      match_labels = {
        app = "${local.instance_name}-postgres"
      }
    }

    template {
      metadata {
        labels = {
          app = "${local.instance_name}-postgres"
        }
      }

      spec {
        # Makes the NFS subdirectory writable by postgres's uid/gid (999).
        security_context {
          fs_group = 999
        }

        container {
          name  = "postgres"
          image = var.postgres_image

          env {
            name  = "PGDATA"
            value = "/var/lib/postgresql/data/pgdata"
          }

          env_from {
            secret_ref {
              name = kubernetes_secret.postgres.metadata[0].name
            }
          }

          port {
            container_port = 5432
          }

          volume_mount {
            name       = "data"
            mount_path = "/var/lib/postgresql/data"
            # Keeps NFS's own directory entries out of PGDATA, which Postgres rejects.
            sub_path = "pgdata"
          }

          readiness_probe {
            exec {
              command = ["pg_isready", "-U", "auth_api"]
            }
            initial_delay_seconds = 5
            period_seconds        = 10
            timeout_seconds       = 5
            failure_threshold     = 3
          }
        }
      }
    }

    volume_claim_template {
      metadata {
        name = "data"
      }
      spec {
        access_modes       = ["ReadWriteOnce"]
        storage_class_name = "nfs-csi"
        resources {
          requests = {
            storage = var.postgres_storage_size
          }
        }
      }
    }
  }
}
