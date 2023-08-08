<div align="center">
  <img src="./icon.svg" alt="ONF Icon" width="200" height="200">
</div>
<br/>
<div align="center">
  <a href="https://charmhub.io/sdcore-udm"><img src="https://charmhub.io/sdcore-udm/badge.svg" alt="CharmHub Badge"></a>
  <a href="https://github.com/canonical/sdcore-udm-operator/actions/workflows/publish-charm.yaml">
    <img src="https://github.com/canonical/sdcore-udm-operator/actions/workflows/publish-charm.yaml/badge.svg?branch=main" alt=".github/workflows/publish-charm.yaml">
  </a>
  <br/>
  <br/>
  <h1>SD-Core UDM Operator</h1>
</div>

A Charmed Operator for SD-Core's Unified Data Manager (UDM) component.

## Usage

```bash
juju deploy mongodb-k8s --channel 5/edge --trust
juju deploy sdcore-nrf --channel edge --trust
juju deploy sdcore-udm --channel edge --trust

juju integrate sdcore-nrf mongodb-k8s
juju integrate sdcore-udm:fiveg_nrf sdcore-nrf
```

### Optional

```bash
juju deploy self-signed-certificates --channel=edge
juju integrate sdcore-udm:certificates self-signed-certificates:certificates
```

## Get the Home Network Public Key
```bash
juju run sdcore-udm/leader get-home-network-public-key
```

## Image

**udm**: `ghcr.io/canonical/sdcore-udm:1.3`
