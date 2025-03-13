#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charmed operator for the Aether SD-Core UDM service for K8s."""

import logging
from ipaddress import IPv4Address
from subprocess import check_output
from typing import List, Optional, cast

from charms.loki_k8s.v1.loki_push_api import LogForwarder
from charms.prometheus_k8s.v0.prometheus_scrape import (
    MetricsEndpointProvider,
)
from charms.sdcore_nms_k8s.v0.sdcore_config import (
    SdcoreConfigRequires,
)
from charms.sdcore_nrf_k8s.v0.fiveg_nrf import NRFRequires
from charms.tls_certificates_interface.v4.tls_certificates import (
    Certificate,
    CertificateRequestAttributes,
    PrivateKey,
    TLSCertificatesRequiresV4,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from jinja2 import Environment, FileSystemLoader
from ops import ActiveStatus, BlockedStatus, CollectStatusEvent, ModelError, WaitingStatus, main
from ops.charm import ActionEvent, CharmBase
from ops.framework import EventBase
from ops.pebble import Layer

from key_gen_utils import generate_x25519_private_key

logger = logging.getLogger(__name__)

PROMETHEUS_PORT = 8080
BASE_CONFIG_PATH = "/etc/udm"
CONFIG_FILE_NAME = "udmcfg.yaml"
UDM_SBI_PORT = 29503
NRF_RELATION_NAME = "fiveg_nrf"
TLS_RELATION_NAME = "certificates"
HOME_NETWORK_KEY_NAME = "home_network.key"
HOME_NETWORK_KEY_PATH = f"/etc/udm/{HOME_NETWORK_KEY_NAME}"
CERTS_DIR_PATH = "/support/TLS"  # Certificate paths are hardcoded in UDM code
PRIVATE_KEY_NAME = "udm.key"
CERTIFICATE_NAME = "udm.pem"
CERTIFICATE_COMMON_NAME = "udm.sdcore"
LOGGING_RELATION_NAME = "logging"
SDCORE_CONFIG_RELATION_NAME = "sdcore_config"
WORKLOAD_VERSION_FILE_NAME = "/etc/workload-version"


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
        self._webui_requires = SdcoreConfigRequires(
            charm=self, relation_name=SDCORE_CONFIG_RELATION_NAME
        )
        self._udm_metrics_endpoint = MetricsEndpointProvider(
            self,
            refresh_event=[self.on.update_status],
            jobs=[
                {
                    "static_configs": [{"targets": [f"*:{PROMETHEUS_PORT}"]}],
                }
            ],
        )
        self.unit.set_ports(PROMETHEUS_PORT, UDM_SBI_PORT)
        self._certificates = TLSCertificatesRequiresV4(
            charm=self,
            relationship_name=TLS_RELATION_NAME,
            certificate_requests=[self._get_certificate_request()],
        )
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
            self.on.get_home_network_public_key_action,
            self._on_get_home_network_public_key_action,
        )
        self.framework.observe(
            self._webui_requires.on.webui_url_available, self._configure_sdcore_udm
        )
        self.framework.observe(self.on.sdcore_config_relation_joined, self._configure_sdcore_udm)

    def _configure_sdcore_udm(self, event: EventBase) -> None:
        """Handle Juju events.

        This event handler is called for every event that affects the charm state
        (ex. configuration files, relation data). This method performs a couple of checks
        to make sure that the workload is ready to be started. Then, it configures the UDM
        workload and runs the Pebble services.

        Args:
            event (EventBase): Juju event
        """
        if not self.ready_to_configure():
            logger.info("The preconditions for the configuration are not met yet.")
            return

        if not self._home_network_private_key_stored():
            self._generate_home_network_private_key()

        if not self._certificate_is_available():
            logger.info("The certificate is not available yet.")
            return

        certificate_update_required = self._check_and_update_certificate()

        desired_config_file = self._generate_udm_config_file()
        if config_update_required := self._is_config_update_required(desired_config_file):
            self._push_config_file(content=desired_config_file)

        should_restart = config_update_required or certificate_update_required
        self._configure_pebble(restart=should_restart)

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

        if invalid_configs := self._get_invalid_configs():
            event.add_status(
                BlockedStatus(f"The following configurations are not valid: {invalid_configs}")
            )
            logger.info("The following configurations are not valid: %s", invalid_configs)
            return

        self.unit.set_workload_version(self._get_workload_version())

        if missing_relations := self._missing_relations():
            event.add_status(
                BlockedStatus(f"Waiting for {', '.join(missing_relations)} relation(s)")
            )
            logger.info("Waiting for %s  relation(s)", ", ".join(missing_relations))
            return

        if not self._nrf_is_available():
            event.add_status(WaitingStatus("Waiting for NRF endpoint to be available"))
            logger.info("Waiting for NRF endpoint to be available")
            return

        if not self._webui_data_is_available:
            event.add_status(WaitingStatus("Waiting for Webui data to be available"))
            logger.info("Waiting for Webui data to be available")
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

        if not self._certificate_is_available():
            event.add_status(WaitingStatus("Waiting for certificates to be available"))
            logger.info("Waiting for certificates to be available")
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

    def ready_to_configure(self) -> bool:
        """Return whether the preconditions are met to proceed with the configuration.

        Returns:
            ready_to_configure: True if all conditions are met else False
        """
        if not self._container.can_connect():
            return False

        if self._get_invalid_configs():
            return False

        if self._missing_relations():
            return False

        if not self._nrf_is_available():
            return False

        if not self._webui_data_is_available:
            return False

        if not self._storage_is_attached():
            return False

        if not _get_pod_ip():
            return False

        return True

    def _check_and_update_certificate(self) -> bool:
        """Check if the certificate or private key needs an update and perform the update.

        This method retrieves the currently assigned certificate and private key associated with
        the charm's TLS relation. It checks whether the certificate or private key has changed
        or needs to be updated. If an update is necessary, the new certificate or private key is
        stored.

        Returns:
            bool: True if either the certificate or the private key was updated, False otherwise.
        """
        provider_certificate, private_key = self._certificates.get_assigned_certificate(
            certificate_request=self._get_certificate_request()
        )
        if not provider_certificate or not private_key:
            logger.debug("Certificate or private key is not available")
            return False
        if certificate_update_required := self._is_certificate_update_required(
            provider_certificate.certificate
        ):
            self._store_certificate(certificate=provider_certificate.certificate)
        if private_key_update_required := self._is_private_key_update_required(private_key):
            self._store_private_key(private_key=private_key)
        return certificate_update_required or private_key_update_required

    @staticmethod
    def _get_certificate_request() -> CertificateRequestAttributes:
        return CertificateRequestAttributes(
            common_name=CERTIFICATE_COMMON_NAME,
            sans_dns=frozenset([CERTIFICATE_COMMON_NAME]),
        )

    def _missing_relations(self) -> List[str]:
        """Return list of missing relations.

        If all the relations are created, it returns an empty list.

        Returns:
            list: missing relation names.
        """
        missing_relations = []
        for relation in [NRF_RELATION_NAME, TLS_RELATION_NAME, SDCORE_CONFIG_RELATION_NAME]:
            if not self._relation_is_created(relation):
                missing_relations.append(relation)
        return missing_relations

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

    def _is_certificate_update_required(self, certificate: Certificate) -> bool:
        return self._get_existing_certificate() != certificate

    def _is_private_key_update_required(self, private_key: PrivateKey) -> bool:
        return self._get_existing_private_key() != private_key

    def _get_existing_certificate(self) -> Optional[Certificate]:
        return self._get_stored_certificate() if self._certificate_is_stored() else None

    def _get_existing_private_key(self) -> Optional[PrivateKey]:
        return self._get_stored_private_key() if self._private_key_is_stored() else None

    def _is_config_update_required(self, content: str) -> bool:
        """Decide whether config update is required by checking existence and config content.

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
        """Handle creation of the SMF config file based on a given template.

        Returns:
            content (str): desired config file content
        """
        if not self._nrf_requires.nrf_url:
            return ""
        if not (pod_ip := _get_pod_ip()):
            return ""
        if not self._webui_requires.webui_url:
            return ""
        if not (log_level := self._get_log_level_config()):
            return ""

        return self._render_config_file(
            nrf_url=self._nrf_requires.nrf_url,
            udm_sbi_port=UDM_SBI_PORT,
            pod_ip=pod_ip,
            scheme="https",
            _home_network_private_key=self._get_home_network_private_key(),
            webui_uri=self._webui_requires.webui_url,
            log_level=log_level,
        )

    def _on_certificates_relation_broken(self, event: EventBase) -> None:
        """Delete TLS related artifacts and reconfigures workload."""
        if not self._container.can_connect():
            event.defer()
            return
        self._delete_private_key()
        self._delete_certificate()

    def _certificate_is_available(self) -> bool:
        cert, key = self._certificates.get_assigned_certificate(
            certificate_request=self._get_certificate_request()
        )
        return bool(cert and key)

    def _delete_private_key(self) -> None:
        """Remove private key from workload."""
        if not self._private_key_is_stored():
            return
        self._container.remove_path(path=f"{CERTS_DIR_PATH}/{PRIVATE_KEY_NAME}")
        logger.info("Removed private key from workload")

    def _delete_certificate(self) -> None:
        """Delete certificate from workload."""
        if not self._certificate_is_stored():
            return
        self._container.remove_path(path=f"{CERTS_DIR_PATH}/{CERTIFICATE_NAME}")
        logger.info("Removed certificate from workload")

    def _private_key_is_stored(self) -> bool:
        """Return whether private key is stored in workload."""
        return self._container.exists(path=f"{CERTS_DIR_PATH}/{PRIVATE_KEY_NAME}")

    def _get_stored_certificate(self) -> Certificate:
        cert_string = str(self._container.pull(path=f"{CERTS_DIR_PATH}/{CERTIFICATE_NAME}").read())
        return Certificate.from_string(cert_string)

    def _get_stored_private_key(self) -> PrivateKey:
        key_string = str(self._container.pull(path=f"{CERTS_DIR_PATH}/{PRIVATE_KEY_NAME}").read())
        return PrivateKey.from_string(key_string)

    def _certificate_is_stored(self) -> bool:
        """Return whether certificate is stored in workload."""
        return self._container.exists(path=f"{CERTS_DIR_PATH}/{CERTIFICATE_NAME}")

    def _store_certificate(self, certificate: Certificate) -> None:
        """Store certificate in workload."""
        self._container.push(path=f"{CERTS_DIR_PATH}/{CERTIFICATE_NAME}", source=str(certificate))
        logger.info("Pushed certificate to workload")

    def _store_private_key(self, private_key: PrivateKey) -> None:
        """Store private key in workload."""
        self._container.push(
            path=f"{CERTS_DIR_PATH}/{PRIVATE_KEY_NAME}",
            source=str(private_key),
        )
        logger.info("Pushed private key to workload")

    def _get_workload_version(self) -> str:
        """Return the workload version.

        Checks for the presence of /etc/workload-version file
        and if present, returns the contents of that file. If
        the file is not present, an empty string is returned.

        Returns:
            string: A human readable string representing the
            version of the workload
        """
        if self._container.exists(path=f"{WORKLOAD_VERSION_FILE_NAME}"):
            version_file_content = self._container.pull(
                path=f"{WORKLOAD_VERSION_FILE_NAME}"
            ).read()
            return version_file_content
        return ""

    def _get_invalid_configs(self) -> list[str]:
        """Return list of invalid configurations.

        Returns:
            list: List of strings matching config keys.
        """
        invalid_configs = []
        if not self._is_log_level_valid():
            invalid_configs.append("log-level")
        return invalid_configs

    def _get_log_level_config(self) -> Optional[str]:
        return cast(Optional[str], self.model.config.get("log-level"))

    def _is_log_level_valid(self) -> bool:
        log_level = self._get_log_level_config()
        return log_level in ["debug", "info", "warn", "error", "fatal", "panic"]

    def _configure_pebble(self, restart: bool = False) -> None:
        """Configure the Pebble layer.

        Args:
            restart (bool): Whether to restart the Pebble service. Defaults to False.
        """
        plan = self._container.get_plan()
        if plan.services != self._pebble_layer.services:
            self._container.add_layer(self._container_name, self._pebble_layer, combine=True)
            self._container.replan()
            logger.info("New layer added: %s", self._pebble_layer)
        if restart:
            self._container.restart(self._service_name)
            logger.info("Restarted container %s", self._service_name)
            return

    def _relation_is_created(self, relation_name: str) -> bool:
        """Return whether a given Juju relation was created.

        Args:
            relation_name (str): Relation name.

        Returns:
            bool: Whether the NRF relation was created.
        """
        return bool(self.model.get_relation(relation_name))

    def _nrf_is_available(self) -> bool:
        """Return whether the NRF endpoint is available.

        Returns:
            bool: whether the NRF endpoint is available.
        """
        return bool(self._nrf_requires.nrf_url)

    @property
    def _webui_data_is_available(self) -> bool:
        return bool(self._webui_requires.webui_url)

    def _storage_is_attached(self) -> bool:
        """Return whether storage is attached to the workload container.

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
        webui_uri: str,
        log_level: str,
    ) -> str:
        """Render the config file content.

        Args:
            nrf_url (str): NRF URL.
            udm_sbi_port (int): UDM SBI port.
            pod_ip (str): UDM pod IPv4.
            scheme (str): SBI interface scheme ("http" or "https")
            webui_uri (str) : URL of the Webui
            log_level (str): Log level for the AMF.

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
            webui_uri=webui_uri,
            log_level=log_level,
        )

    def _config_file_is_written(self) -> bool:
        """Return whether the config file was written to the workload container.

        Returns:
            bool: Whether the config file was written.
        """
        return bool(self._container.exists(f"{BASE_CONFIG_PATH}/{CONFIG_FILE_NAME}"))

    def _config_file_content_matches(self, content: str) -> bool:
        """Return whether the config file content matches the provided content.

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
                "public-key": self._get_home_network_public_key(),
            }
        )

    def _generate_home_network_private_key(self) -> None:
        """Generate and stores Home Network private key on the container."""
        private_key_string = generate_x25519_private_key()
        self._container.push(
            path=f"{HOME_NETWORK_KEY_PATH}",
            source=private_key_string,
        )
        logger.info("Pushed home network private key to workload")

    def _home_network_private_key_stored(self) -> bool:
        """Return whether the Home Network private key is stored.

        Returns:
            bool: Whether the key is stored on the container.
        """
        return self._container.exists(path=f"{HOME_NETWORK_KEY_PATH}")

    def _get_home_network_private_key(self) -> str:
        """Get the Home Network private key from the container.

        Returns:
            str: The Home Network private key in hexadecimal.
        """
        return str(self._container.pull(path=f"{HOME_NETWORK_KEY_PATH}").read())

    def _get_home_network_public_key(self) -> str:
        """Calculate the Home Network public key from the private key.

        Returns:
            str: The Home Network public key in hexadecimal.
        """
        private_key_string = self._get_home_network_private_key()
        private_bytes = bytes.fromhex(private_key_string)
        private_key = X25519PrivateKey.from_private_bytes(private_bytes)
        public_key = private_key.public_key()
        public_bytes = public_key.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        public_key_string = public_bytes.hex()
        return public_key_string

    @property
    def _pebble_layer(self) -> Layer:
        """Return pebble layer for the charm.

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
                        "command": f"/bin/udm --cfg {BASE_CONFIG_PATH}/{CONFIG_FILE_NAME}",
                        "environment": self._environment_variables,
                    },
                },
            }
        )

    @property
    def _environment_variables(self) -> dict:
        return {
            "POD_IP": _get_pod_ip(),
            "MANAGED_BY_CONFIG_POD": "true",
        }


def _get_pod_ip() -> Optional[str]:
    """Return the pod IP using juju client.

    Returns:
        str: The pod IP.
    """
    ip_address = check_output(["unit-get", "private-address"])
    return str(IPv4Address(ip_address.decode().strip())) if ip_address else None


if __name__ == "__main__":
    main(UDMOperatorCharm)
