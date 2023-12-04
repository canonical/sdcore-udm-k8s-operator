# SD-Core UDM Operator (k8s)
[![CharmHub Badge](https://charmhub.io/sdcore-udm/badge.svg)](https://charmhub.io/sdcore-udm)

A Charmed Operator for SD-Core's Unified Data Manager (UDM) component.

## Usage

```bash
juju deploy mongodb-k8s --channel 5/edge --trust
juju deploy sdcore-nrf --channel edge
juju deploy sdcore-udm --channel edge
juju deploy self-signed-certificates --channel=beta

juju integrate sdcore-nrf mongodb-k8s
juju integrate sdcore-nrf:certificates self-signed-certificates:certificates
juju integrate sdcore-udm:fiveg_nrf sdcore-nrf
juju integrate sdcore-udm:certificates self-signed-certificates:certificates
```

## Get the Home Network Public Key
```bash
juju run sdcore-udm/leader get-home-network-public-key
```

## Image

**udm**: `ghcr.io/canonical/sdcore-udm:1.3`
