# SD-Core UDM Operator (k8s)
[![CharmHub Badge](https://charmhub.io/sdcore-udm-k8s/badge.svg)](https://charmhub.io/sdcore-udm-k8s)

A Charmed Operator for SD-Core's Unified Data Manager (UDM) component for K8s.

## Usage

```bash
juju deploy mongodb-k8s --channel 6/beta --trust
juju deploy sdcore-nrf-k8s --channel=1.5/edge
juju deploy sdcore-udm-k8s --channel=1.5/edge
juju deploy sdcore-webui-k8s --channel=1.5/edge
juju integrate sdcore-webui-k8s:common_database mongodb-k8s:database
juju integrate sdcore-webui-k8s:auth_database mongodb-k8s:database
juju deploy self-signed-certificates

juju integrate sdcore-nrf-k8s mongodb-k8s
juju integrate sdcore-nrf-k8s:certificates self-signed-certificates:certificates
juju integrate sdcore-nrf-k8s:sdcore_config sdcore-webui-k8s:sdcore-config
juju integrate sdcore-udm-k8s:fiveg_nrf sdcore-nrf-k8s:fiveg_nrf
juju integrate sdcore-udm-k8s:certificates self-signed-certificates:certificates
juju integrate sdcore-udm-k8s:sdcore_config sdcore-webui-k8s:sdcore-config
```

## Get the Home Network Public Key
```bash
juju run sdcore-udm-k8s/leader get-home-network-public-key
```

## Image

**udm**: `ghcr.io/canonical/sdcore-udm:1.4.0`

