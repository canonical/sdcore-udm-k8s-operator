#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charmed operator for the 5G UDM service."""

import logging
from ipaddress import IPv4Address
from subprocess import check_output
from typing import Optional

from charms.observability_libs.v1.kubernetes_service_patch import (  # type: ignore[import]  # noqa: E501
    KubernetesServicePatch,
)
from charms.sdcore_nrf.v0.fiveg_nrf import NRFRequires  # type: ignore[import]
from charms.tls_certificates_interface.v2.tls_certificates import (  # type: ignore[import]
    CertificateAvailableEvent,
    CertificateExpiringEvent,
    TLSCertificatesRequiresV2,
    generate_csr,
    generate_private_key,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from jinja2 import Environment, FileSystemLoader
from lightkube.models.core_v1 import ServicePort
from ops.charm import ActionEvent, CharmBase
from ops.framework import EventBase
from ops.main import main
from ops.model import ActiveStatus, BlockedStatus, WaitingStatus
from ops.pebble import Layer

from key_gen_utils import generate_x25519_private_key

logger = logging.getLogger(__name__)

BASE_CONFIG_PATH = "/etc/udm"
CONFIG_FILE_NAME = "udmcfg.yaml"
UDM_SBI_PORT = 29503
NRF_RELATION_NAME = "fiveg_nrf"
HOME_NETWORK_KEY_NAME = "home_network.key"
HOME_NETWORK_KEY_PATH = f"/etc/udm/{HOME_NETWORK_KEY_NAME}"
CERTS_DIR_PATH = "/support/TLS"  # Certificate paths are hardcoded in UDM code
PRIVATE_KEY_NAME = "udm.key"
CSR_NAME = "udm.csr"
CERTIFICATE_NAME = "udm.pem"
CERTIFICATE_COMMON_NAME = "udm.sdcore"


class UDMOperatorCharm(CharmBase):
    """Charm the service."""

    def __init__(self, *args):
        super().__init__(*args)
        if not self.unit.is_leader():
            raise NotImplementedError("Scaling is not implemented for this charm")
        self._container_name = self._service_name = "udm"
        self._container = self.unit.get_container(self._container_name)
        self._nrf_requires = NRFRequires(charm=self, relation_name=NRF_RELATION_NAME)
        self._service_patcher = KubernetesServicePatch(
            charm=self,
            ports=[ServicePort(name="sbi", port=UDM_SBI_PORT)],
        )
        self._certificates = TLSCertificatesRequiresV2(self, "certificates")
        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.on.udm_pebble_ready, self._configure_sdcore_udm)
        self.framework.observe(self.on.fiveg_nrf_relation_joined, self._configure_sdcore_udm)
        self.framework.observe(self._nrf_requires.on.nrf_available, self._configure_sdcore_udm)
        self.framework.observe(
            self.on.certificates_relation_created, self._on_certificates_relation_created
        )
        self.framework.observe(
            self.on.certificates_relation_joined, self._on_certificates_relation_joined
        )
        self.framework.observe(
            self.on.certificates_relation_broken, self._on_certificates_relation_broken
        )
        self.framework.observe(
            self._certificates.on.certificate_available, self._on_certificate_available
        )
        self.framework.observe(
            self._certificates.on.certificate_expiring, self._on_certificate_expiring
        )
        self.framework.observe(
            self.on.get_home_network_public_key_action,
            self._on_get_home_network_public_key_action,
        )

    def _on_install(self, event: EventBase) -> None:
        """Handles the install event.

        Args:
            event (EventBase): Juju event.
        """
        if not self._container.can_connect():
            self.unit.status = WaitingStatus("Waiting for container to be ready")
            event.defer()
            return
        self._generate_home_network_private_key()

    def _configure_sdcore_udm(self, event: EventBase) -> None:
        """Adds Pebble layer and manages Juju unit status.

        Args:
            event (EventBase): Juju event.
        """
        if not self._container.can_connect():
            self.unit.status = WaitingStatus("Waiting for container to be ready")
            return
        if not self._nrf_relation_is_created():
            self.unit.status = BlockedStatus("Waiting for `fiveg_nrf` relation to be created")
            return
        if not self._nrf_is_available():
            self.unit.status = WaitingStatus("Waiting for NRF endpoint to be available")
            return
        if not self._storage_is_attached():
            self.unit.status = WaitingStatus("Waiting for the storage to be attached")
            event.defer()
            return
        if not _get_pod_ip():
            self.unit.status = WaitingStatus("Waiting for pod IP address to be available")
            event.defer()
            return
        if not self._home_network_private_key_stored():
            self.unit.status = WaitingStatus(
                "Waiting for home network private key to be available"
            )
            event.defer()
            return
        restart = self._update_config_file()
        self._configure_pebble(restart=restart)
        self.unit.status = ActiveStatus()

    def _on_certificates_relation_created(self, event: EventBase) -> None:
        """Generates Private key."""
        if not self._container.can_connect():
            event.defer()
            return
        self._generate_private_key()

    def _on_certificates_relation_broken(self, event: EventBase) -> None:
        """Deletes TLS related artifacts and reconfigures workload."""
        if not self._container.can_connect():
            event.defer()
            return
        self._delete_private_key()
        self._delete_csr()
        self._delete_certificate()
        self._configure_sdcore_udm(event)

    def _on_certificates_relation_joined(self, event: EventBase) -> None:
        """Generates CSR and requests new certificate."""
        if not self._container.can_connect():
            event.defer()
            return
        if not self._private_key_is_stored():
            event.defer()
            return
        self._request_new_certificate()

    def _on_certificate_available(self, event: CertificateAvailableEvent) -> None:
        """Pushes certificate to workload and configures workload."""
        if not self._container.can_connect():
            event.defer()
            return
        if not self._csr_is_stored():
            logger.warning("Certificate is available but no CSR is stored")
            return
        if event.certificate_signing_request != self._get_stored_csr():
            logger.debug("Stored CSR doesn't match one in certificate available event")
            return
        self._store_certificate(event.certificate)
        self._configure_sdcore_udm(event)

    def _on_certificate_expiring(self, event: CertificateExpiringEvent) -> None:
        """Requests new certificate."""
        if not self._container.can_connect():
            event.defer()
            return
        if event.certificate != self._get_stored_certificate():
            logger.debug("Expiring certificate is not the one stored")
            return
        self._request_new_certificate()

    def _generate_private_key(self) -> None:
        """Generates and stores private key."""
        private_key = generate_private_key()
        self._store_private_key(private_key)

    def _request_new_certificate(self) -> None:
        """Generates and stores CSR, and uses it to request a new certificate."""
        private_key = self._get_stored_private_key()
        csr = generate_csr(
            private_key=private_key,
            subject=CERTIFICATE_COMMON_NAME,
            sans_dns=[CERTIFICATE_COMMON_NAME],
        )
        self._store_csr(csr)
        self._certificates.request_certificate_creation(certificate_signing_request=csr)

    def _delete_private_key(self) -> None:
        """Removes private key from workload."""
        if not self._private_key_is_stored():
            return
        self._container.remove_path(path=f"{CERTS_DIR_PATH}/{PRIVATE_KEY_NAME}")
        logger.info("Removed private key from workload")

    def _delete_csr(self) -> None:
        """Deletes CSR from workload."""
        if not self._csr_is_stored():
            return
        self._container.remove_path(path=f"{CERTS_DIR_PATH}/{CSR_NAME}")
        logger.info("Removed CSR from workload")

    def _delete_certificate(self) -> None:
        """Deletes certificate from workload."""
        if not self._certificate_is_stored():
            return
        self._container.remove_path(path=f"{CERTS_DIR_PATH}/{CERTIFICATE_NAME}")
        logger.info("Removed certificate from workload")

    def _private_key_is_stored(self) -> bool:
        """Returns whether private key is stored in workload."""
        return self._container.exists(path=f"{CERTS_DIR_PATH}/{PRIVATE_KEY_NAME}")

    def _csr_is_stored(self) -> bool:
        """Returns whether CSR is stored in workload."""
        return self._container.exists(path=f"{CERTS_DIR_PATH}/{CSR_NAME}")

    def _get_stored_certificate(self) -> str:
        """Returns stored certificate."""
        return str(self._container.pull(path=f"{CERTS_DIR_PATH}/{CERTIFICATE_NAME}").read())

    def _get_stored_csr(self) -> str:
        """Returns stored CSR."""
        return str(self._container.pull(path=f"{CERTS_DIR_PATH}/{CSR_NAME}").read())

    def _get_stored_private_key(self) -> bytes:
        """Returns stored private key."""
        return str(
            self._container.pull(path=f"{CERTS_DIR_PATH}/{PRIVATE_KEY_NAME}").read()
        ).encode()

    def _certificate_is_stored(self) -> bool:
        """Returns whether certificate is stored in workload."""
        return self._container.exists(path=f"{CERTS_DIR_PATH}/{CERTIFICATE_NAME}")

    def _store_certificate(self, certificate: str) -> None:
        """Stores certificate in workload."""
        self._container.push(path=f"{CERTS_DIR_PATH}/{CERTIFICATE_NAME}", source=certificate)
        logger.info("Pushed certificate pushed to workload")

    def _store_private_key(self, private_key: bytes) -> None:
        """Stores private key in workload."""
        self._container.push(
            path=f"{CERTS_DIR_PATH}/{PRIVATE_KEY_NAME}",
            source=private_key.decode(),
        )
        logger.info("Pushed private key to workload")

    def _store_csr(self, csr: bytes) -> None:
        """Stores CSR in workload."""
        self._container.push(path=f"{CERTS_DIR_PATH}/{CSR_NAME}", source=csr.decode().strip())
        logger.info("Pushed CSR to workload")

    def _configure_pebble(self, restart: bool = False) -> None:
        """Configure the Pebble layer.

        Args:
            restart (bool): Whether to restart the Pebble service. Defaults to False.
        """
        self._container.add_layer(self._container_name, self._pebble_layer, combine=True)
        if restart:
            self._container.restart(self._service_name)
            logger.info("Restarted container %s", self._service_name)
            return
        self._container.replan()

    def _nrf_relation_is_created(self) -> bool:
        """Returns whether NRF Juju relation was crated.

        Returns:
            bool: Whether the NRF relation was created.
        """
        return bool(self.model.get_relation(NRF_RELATION_NAME))

    def _nrf_is_available(self) -> bool:
        """Returns whether the NRF endpoint is available.

        Returns:
            bool: whether the NRF endpoint is available.
        """
        return bool(self._nrf_requires.nrf_url)

    def _storage_is_attached(self) -> bool:
        """Returns whether storage is attached to the workload container.

        Returns:
            bool: Whether storage is attached.
        """
        return self._container.exists(path=BASE_CONFIG_PATH)

    def _update_config_file(self) -> bool:
        """Updates config file.

        Writes the config file if it does not exist or
        the content does not match.

        Returns:
            bool: True if config file was updated, False otherwise.
        """
        content = self._render_config_file(
            nrf_url=self._nrf_requires.nrf_url,
            udm_sbi_port=UDM_SBI_PORT,
            pod_ip=_get_pod_ip(),  # type: ignore[arg-type]
            scheme="https" if self._certificate_is_stored() else "http",
            _home_network_private_key=self._get_home_network_private_key(),  # type: ignore[arg-type] # noqa: E501
        )
        if not self._config_file_is_written() or not self._config_file_content_matches(
            content=content
        ):
            self._write_config_file(content=content)
            return True
        return False

    def _render_config_file(
        self,
        *,
        nrf_url: str,
        udm_sbi_port: int,
        pod_ip: str,
        scheme: str,
        _home_network_private_key: str,
    ) -> str:
        """Renders the config file content.

        Args:
            nrf_url (str): NRF URL.
            udm_sbi_port (int): UDM SBI port.
            pod_ip (str): UDM pod IPv4.
            scheme (str): SBI interface scheme ("http" or "https")

        Returns:
            str: Config file content.
        """
        jinja2_env = Environment(loader=FileSystemLoader("src/templates"))
        template = jinja2_env.get_template("udmcfg.yaml.j2")
        return template.render(
            nrf_url=nrf_url,
            udm_sbi_port=udm_sbi_port,
            pod_ip=pod_ip,
            scheme=scheme,
            _home_network_private_key=_home_network_private_key,
        )

    def _write_config_file(self, content: str) -> None:
        """Writes config file to workload.

        Args:
            content (str): Config file content.
        """
        self._container.push(
            path=f"{BASE_CONFIG_PATH}/{CONFIG_FILE_NAME}",
            source=content,
        )
        logger.info("Pushed: %s to workload.", CONFIG_FILE_NAME)

    def _config_file_is_written(self) -> bool:
        """Returns whether the config file was written to the workload container.

        Returns:
            bool: Whether the config file was written.
        """
        return bool(self._container.exists(f"{BASE_CONFIG_PATH}/{CONFIG_FILE_NAME}"))

    def _config_file_content_matches(self, content: str) -> bool:
        """Returns whether the config file content matches the provided content.

        Args:
            content (str): Config file content.

        Returns:
            bool: Whether the config file content matches.
        """
        existing_content = self._container.pull(path=f"{BASE_CONFIG_PATH}/{CONFIG_FILE_NAME}")
        return existing_content.read() == content

    def _on_get_home_network_public_key_action(self, event: ActionEvent) -> None:
        if not self._container.can_connect():
            event.fail(message="Container is not ready yet.")
            return
        if not self._home_network_private_key_stored():
            event.fail(message="Home network private key is not stored yet.")
            return
        event.set_results(
            {
                "public-key": self._get_home_network_public_key(),  # type: ignore[arg-type] # noqa: E501
            }
        )

    def _generate_home_network_private_key(self) -> None:
        """Generates and stores Home Network private key on the container."""
        private_key_string = generate_x25519_private_key()
        self._container.push(
            path=f"{HOME_NETWORK_KEY_PATH}",
            source=private_key_string,
        )
        logger.info("Pushed home network private key to workload")

    def _home_network_private_key_stored(self) -> bool:
        """Returns whether the Home Network private key is stored.

        Returns:
            bool: Whether the key is stored on the container.
        """
        return self._container.exists(path=f"{HOME_NETWORK_KEY_PATH}")

    def _get_home_network_private_key(self) -> str:
        """Gets the Home Network private key from the container.

        Returns:
            str: The Home Network private key in hexadecimal.
        """
        return str(self._container.pull(path=f"{HOME_NETWORK_KEY_PATH}").read())

    def _get_home_network_public_key(self) -> str:
        """Calculates the Home Network public key from the private key.

        Returns:
            str: The Home Network public key in hexadecimal.
        """
        private_key_string = self._get_home_network_private_key()
        private_bytes = bytes.fromhex(private_key_string)  # type: ignore[arg-type]
        private_key = X25519PrivateKey.from_private_bytes(private_bytes)
        public_key = private_key.public_key()
        public_bytes = public_key.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        public_key_string = public_bytes.hex()
        return public_key_string

    @property
    def _pebble_layer(self) -> Layer:
        """Returns pebble layer for the charm.

        Returns:
            Layer: Pebble Layer.
        """
        return Layer(
            {
                "summary": "udm layer",
                "description": "pebble config layer for udm",
                "services": {
                    self._service_name: {
                        "override": "replace",
                        "startup": "enabled",
                        "command": f"/bin/udm --udmcfg {BASE_CONFIG_PATH}/{CONFIG_FILE_NAME}",
                        "environment": self._environment_variables,
                    },
                },
            }
        )

    @property
    def _environment_variables(self) -> dict:
        return {
            "GRPC_GO_LOG_VERBOSITY_LEVEL": "99",
            "GRPC_GO_LOG_SEVERITY_LEVEL": "info",
            "GRPC_TRACE": "all",
            "GRPC_VERBOSITY": "debug",
            "POD_IP": _get_pod_ip(),
            "MANAGED_BY_CONFIG_POD": "true",
        }


def _get_pod_ip() -> Optional[str]:
    """Returns the pod IP using juju client.

    Returns:
        str: The pod IP.
    """
    ip_address = check_output(["unit-get", "private-address"])
    return str(IPv4Address(ip_address.decode().strip())) if ip_address else None


if __name__ == "__main__":
    main(UDMOperatorCharm)
