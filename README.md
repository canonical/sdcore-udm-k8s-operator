# SD-Core UDM Operator for K8s
[![CharmHub Badge](https://charmhub.io/sdcore-udm-k8s/badge.svg)](https://charmhub.io/sdcore-udm-k8s)

A Charmed Operator for SD-Core's Unified Data Manager (UDM) component for K8s.

## Usage

```bash
juju deploy mongodb-k8s --channel 5/edge --trust
juju deploy sdcore-nrf-k8s --channel edge
juju deploy sdcore-udm-k8s --channel edge
juju deploy self-signed-certificates --channel=beta

juju integrate sdcore-nrf-k8s mongodb-k8s
juju integrate sdcore-nrf-k8s:certificates self-signed-certificates:certificates
juju integrate sdcore-udm-k8s:fiveg_nrf sdcore-nrf-k8s:fiveg_nrf
juju integrate sdcore-udm-k8s:certificates self-signed-certificates:certificates
```

## Get the Home Network Public Key
```bash
juju run sdcore-udm-k8s/leader get-home-network-public-key
```

## Image

**udm**: `ghcr.io/canonical/sdcore-udm:1.3`
