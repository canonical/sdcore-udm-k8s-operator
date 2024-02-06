resource "juju_application" "udm" {
  name  = "udm"
  model = var.model_name

  charm {
    name    = "sdcore-udm-k8s"
    channel = var.channel
  }

  units = 1
  trust = true
}

resource "juju_integration" "udm-certs" {
  model = var.model_name

  application {
    name     = juju_application.udm.name
    endpoint = "certificates"
  }

  application {
    name     = var.certs_application_name
    endpoint = "certificates"
  }
}

resource "juju_integration" "udm-nrf" {
  model = var.model_name

  application {
    name     = juju_application.udm.name
    endpoint = "fiveg_nrf"
  }

  application {
    name     = var.nrf_application_name
    endpoint = "fiveg-nrf"
  }
}

