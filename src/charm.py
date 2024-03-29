#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charmed operator for the 5G UDM service for K8s."""

import logging
from ipaddress import IPv4Address
from subprocess import check_output
from typing import Optional

from charms.loki_k8s.v1.loki_push_api import LogForwarder  # type: ignore[import]
from charms.sdcore_nrf_k8s.v0.fiveg_nrf import NRFRequires  # type: ignore[import]
from charms.tls_certificates_interface.v3.tls_certificates import (  # type: ignore[import]
    CertificateExpiringEvent,
    TLSCertificatesRequiresV3,
    generate_csr,
    generate_private_key,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from jinja2 import Environment, FileSystemLoader
from ops import ActiveStatus, BlockedStatus, CollectStatusEvent, ModelError, WaitingStatus
from ops.charm import ActionEvent, CharmBase
from ops.framework import EventBase
from ops.main import main
from ops.pebble import Layer

from key_gen_utils import generate_x25519_private_key

logger = logging.getLogger(__name__)

BASE_CONFIG_PATH = "/etc/udm"
CONFIG_FILE_NAME = "udmcfg.yaml"
UDM_SBI_PORT = 29503
NRF_RELATION_NAME = "fiveg_nrf"
TLS_RELATION_NAME = "certificates"
HOME_NETWORK_KEY_NAME = "home_network.key"
HOME_NETWORK_KEY_PATH = f"/etc/udm/{HOME_NETWORK_KEY_NAME}"
CERTS_DIR_PATH = "/support/TLS"  # Certificate paths are hardcoded in UDM code
PRIVATE_KEY_NAME = "udm.key"
CSR_NAME = "udm.csr"
CERTIFICATE_NAME = "udm.pem"
CERTIFICATE_COMMON_NAME = "udm.sdcore"
LOGGING_RELATION_NAME = "logging"


class UDMOperatorCharm(CharmBase):
    """Charm the service."""

    def __init__(self, *args):
        super().__init__(*args)
        self.framework.observe(self.on.collect_unit_status, self._on_collect_unit_status)
        if not self.unit.is_leader():
            # NOTE: In cases where leader status is lost before the charm is
            # finished processing all teardown events, this prevents teardown
            # event code from running. Luckily, for this charm, none of the
            # teardown code is necessary to perform if we're removing the
            # charm.
            return
        self._container_name = self._service_name = "udm"
        self._container = self.unit.get_container(self._container_name)
        self._nrf_requires = NRFRequires(charm=self, relation_name=NRF_RELATION_NAME)
        self.unit.set_ports(UDM_SBI_PORT)
        self._certificates = TLSCertificatesRequiresV3(self, "certificates")
        self._logging = LogForwarder(charm=self, relation_name=LOGGING_RELATION_NAME)
        self.framework.observe(self.on.update_status, self._configure_sdcore_udm)
        self.framework.observe(self.on.udm_pebble_ready, self._configure_sdcore_udm)
        self.framework.observe(self.on.fiveg_nrf_relation_joined, self._configure_sdcore_udm)
        self.framework.observe(self._nrf_requires.on.nrf_available, self._configure_sdcore_udm)
        self.framework.observe(self.on.certificates_relation_joined, self._configure_sdcore_udm)
        self.framework.observe(
            self.on.certificates_relation_broken, self._on_certificates_relation_broken
        )
        self.framework.observe(
            self._certificates.on.certificate_available, self._configure_sdcore_udm
        )
        self.framework.observe(
            self._certificates.on.certificate_expiring, self._on_certificate_expiring
        )
        self.framework.observe(
            self.on.get_home_network_public_key_action,
            self._on_get_home_network_public_key_action,
        )

    def _on_collect_unit_status(self, event: CollectStatusEvent):  # noqa C901
        """Check the unit status and set to Unit when CollectStatusEvent is fired.

        Args:
            event: CollectStatusEvent
        """
        if not self.unit.is_leader():
            # NOTE: In cases where leader status is lost before the charm is
            # finished processing all teardown events, this prevents teardown
            # event code from running. Luckily, for this charm, none of the
            # teardown code is necessary to perform if we're removing the
            # charm.
            event.add_status(BlockedStatus("Scaling is not implemented for this charm"))
            logger.info("Scaling is not implemented for this charm")
            return

        if not self._container.can_connect():
            event.add_status(WaitingStatus("Waiting for container to be ready"))
            logger.info("Waiting for container to be ready")
            return

        for relation in [NRF_RELATION_NAME, TLS_RELATION_NAME]:
            if not self._relation_is_created(relation):
                event.add_status(BlockedStatus(f"Waiting for {relation} relation"))
                logger.info(f"Waiting for {relation} relation")
                return

        if not self._nrf_is_available():
            event.add_status(WaitingStatus("Waiting for NRF endpoint to be available"))
            logger.info("Waiting for NRF endpoint to be available")
            return

        if not self._storage_is_attached():
            event.add_status(WaitingStatus("Waiting for the storage to be attached"))
            logger.info("Waiting for the storage to be attached")
            return

        if not _get_pod_ip():
            event.add_status(WaitingStatus("Waiting for pod IP address to be available"))
            logger.info("Waiting for pod IP address to be available")
            return

        if not self._home_network_private_key_stored():
            event.add_status(WaitingStatus("Waiting for home network private key to be available"))
            logger.info("Waiting for home network private key to be available")
            return

        if self._csr_is_stored() and not self._get_current_provider_certificate():
            event.add_status(WaitingStatus("Waiting for certificates to be stored"))
            logger.info("Waiting for certificates to be stored")
            return

        if not self._udm_service_is_running():
            event.add_status(WaitingStatus("Waiting for UDM service to start"))
            logger.info("Waiting for UDM service to start")
            return

        event.add_status(ActiveStatus())

    def _udm_service_is_running(self) -> bool:
        """Check if the UDM service is running.

        Returns:
            bool: Whether the UDM service is running.
        """
        if not self._container.can_connect():
            return False
        try:
            service = self._container.get_service(self._service_name)
        except ModelError:
            return False
        return service.is_running()

    def _configure_sdcore_udm(self, event: EventBase) -> None:  # noqa: C901
        """Adds Pebble layer and manages Juju unit status.

        Args:
            event (EventBase): Juju event.
        """
        if not self.ready_to_configure():
            logger.info("The preconditions for the configuration are not met yet.")
            return

        if not self._home_network_private_key_stored():
            self._generate_home_network_private_key()

        if not self._private_key_is_stored():
            self._generate_private_key()

        if not self._csr_is_stored():
            self._request_new_certificate()

        provider_certificate = self._get_current_provider_certificate()
        if not provider_certificate:
            return

        if certificate_update_required := self._is_certificate_update_required(
            provider_certificate
        ):
            self._store_certificate(certificate=provider_certificate)

        desired_config_file = self._generate_udm_config_file()
        if config_update_required := self._is_config_update_required(desired_config_file):
            self._push_config_file(content=desired_config_file)

        should_restart = config_update_required or certificate_update_required
        self._configure_pebble(restart=should_restart)

    def ready_to_configure(self) -> bool:
        """Returns whether the preconditions are met to proceed with the configuration.

        Returns:
            ready_to_configure: True if all conditions are met else False
        """
        if not self._container.can_connect():
            return False

        for relation in [NRF_RELATION_NAME, TLS_RELATION_NAME]:
            if not self._relation_is_created(relation):
                return False

        if not self._nrf_is_available():
            return False

        if not self._storage_is_attached():
            return False

        if not _get_pod_ip():
            return False

        return True

    def _push_config_file(
        self,
        content: str,
    ) -> None:
        """Push the SMF config file to the container.

        Args:
            content (str): Content of the config file.
        """
        self._container.push(
            path=f"{BASE_CONFIG_PATH}/{CONFIG_FILE_NAME}",
            source=content,
        )
        logger.info("Pushed: %s to workload.", CONFIG_FILE_NAME)

    def _is_certificate_update_required(self, provider_certificate) -> bool:
        """Checks the provided certificate and existing certificate.

        Returns True if update is required.

        Args:
            provider_certificate: str
        Returns:
            True if update is required else False
        """
        return self._get_existing_certificate() != provider_certificate

    def _is_config_update_required(self, content: str) -> bool:
        """Decides whether config update is required by checking existence and config content.

        Args:
            content (str): desired config file content

        Returns:
            True if config update is required else False
        """
        if not self._config_file_is_written() or not self._config_file_content_matches(
            content=content
        ):
            return True
        return False

    def _generate_udm_config_file(self) -> str:
        """Handles creation of the SMF config file based on a given template.

        Returns:
            content (str): desired config file content
        """
        return self._render_config_file(
            nrf_url=self._nrf_requires.nrf_url,
            udm_sbi_port=UDM_SBI_PORT,
            pod_ip=_get_pod_ip(),  # type: ignore[arg-type]
            scheme="https",
            _home_network_private_key=self._get_home_network_private_key(),  # type: ignore[arg-type] # noqa: E501
        )

    def _get_existing_certificate(self) -> str:
        """Returns the existing certificate if present else empty string."""
        return self._get_stored_certificate() if self._certificate_is_stored() else ""

    def _get_current_provider_certificate(self) -> str | None:
        """Compares the current certificate request to what is in the interface.

        Returns the current valid provider certificate if present
        """
        csr = self._get_stored_csr()
        for provider_certificate in self._certificates.get_assigned_certificates():
            if provider_certificate.csr == csr:
                return provider_certificate.certificate
        return None

    def _on_certificates_relation_broken(self, event: EventBase) -> None:
        """Deletes TLS related artifacts and reconfigures workload."""
        if not self._container.can_connect():
            event.defer()
            return
        self._delete_private_key()
        self._delete_csr()
        self._delete_certificate()

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

    def _relation_is_created(self, relation_name: str) -> bool:
        """Returns whether a given Juju relation was created.

        Args:
            relation_name (str): Relation name.

        Returns:
            bool: Whether the NRF relation was created.
        """
        return bool(self.model.get_relation(relation_name))

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
        return self._container.exists(path=BASE_CONFIG_PATH) and self._container.exists(
            path=CERTS_DIR_PATH
        )

    @staticmethod
    def _render_config_file(
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
