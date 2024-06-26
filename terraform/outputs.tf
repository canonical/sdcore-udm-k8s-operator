# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

output "app_name" {
  description = "Name of the deployed application."
  value       = juju_application.sdcore-udm-k8s.name
}

# Required integration endpoints

output "certificates_endpoint" {
  description = "Name of the endpoint to get the X.509 certificate using tls-certificates interface."
  value       = "certificates"
}

output "fiveg_nrf_endpoint" {
  description = "Name of the endpoint to provide fiveg_nrf interface."
  value       = "fiveg_nrf"
}

output "logging_endpoint" {
  description = "Name of the endpoint used to integrate with the Logging provider."
  value       = "logging"
}

output "sdcore_config_endpoint" {
  description = "Name of the endpoint used to integrate with the Webui."
  value       = "sdcore_config"
}

# Provided integration endpoints

output "metrics_endpoint" {
  description = "Exposes the Prometheus metrics endpoint providing telemetry about the UDM instance."
  value       = "metrics-endpoint"
}