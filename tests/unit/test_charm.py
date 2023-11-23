# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
import unittest
from unittest.mock import Mock, PropertyMock, patch

import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from ops import testing
from ops.model import ActiveStatus, BlockedStatus, WaitingStatus

from charm import CONFIG_FILE_NAME, NRF_RELATION_NAME, TLS_RELATION_NAME, UDMOperatorCharm

logger = logging.getLogger(__name__)

VALID_NRF_URL = "https://nrf:443"
EXPECTED_CONFIG_FILE_PATH = "tests/unit/expected_udmcfg.yaml"


class TestCharm(unittest.TestCase):
    @patch(
        "charm.KubernetesServicePatch",
        lambda charm, ports: None,
    )
    def setUp(self):
        self._mock_home_network_private_key = X25519PrivateKey.generate()
        self.maxDiff = None
        self.namespace = "whatever"
        self.metadata = self._get_metadata()
        self.container_name = list(self.metadata["containers"].keys())[0]
        self.harness = testing.Harness(UDMOperatorCharm)
        self.harness.set_model_name(name=self.namespace)
        self.addCleanup(self.harness.cleanup)
        self.harness.set_leader(is_leader=True)
        self.harness.begin()

    @staticmethod
    def _get_metadata() -> dict:
        """Reads `metadata.yaml` and returns it as a dictionary.

        Returns:
            dics: metadata.yaml as a dictionary.
        """
        with open("metadata.yaml", "r") as f:
            data = yaml.safe_load(f)
        return data

    @staticmethod
    def _read_file(path: str) -> str:
        """Reads a file and returns as a string.

        Args:
            path (str): path to the file.

        Returns:
            str: content of the file.
        """
        with open(path, "r") as f:
            content = f.read()
        return content

    def _create_nrf_relation(self) -> int:
        """Creates NRF relation.

        Returns:
            int: relation id.
        """
        relation_id = self.harness.add_relation(
            relation_name=NRF_RELATION_NAME, remote_app="nrf-operator"
        )
        self.harness.add_relation_unit(relation_id=relation_id, remote_unit_name="nrf-operator/0")
        return relation_id

    def _create_certificates_relation(self) -> int:
        """Creates certificates relation.

        Returns:
            int: relation id.
        """
        return self.harness.add_relation(
            relation_name=TLS_RELATION_NAME, remote_app="tls-certificates-operator"
        )

    def _get_home_network_private_key_as_hexa_string(self) -> str:
        """Returns home network private key as hexadecimal string."""
        private_bytes = self._mock_home_network_private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return private_bytes.hex()

    def _get_home_network_public_key_as_hexa_string(self) -> str:
        """Returns home network public key as hexadecimal string."""
        public_key = self._mock_home_network_private_key.public_key()
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        return public_bytes.hex()

    def test_given_cant_connect_to_container_when_on_install_then_status_is_waiting(self):
        self.harness.set_can_connect(container=self.container_name, val=False)

        self.harness.charm._on_install(event=Mock())

        self.assertEqual(
            self.harness.model.unit.status, WaitingStatus("Waiting for container to be ready")
        )

    @patch("cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey.generate")
    def test_given_can_connect_when_on_install_then_home_network_key_is_generated_and_pushed_to_container(  # noqa: E501
        self,
        patch_generate,
    ):
        self.harness.add_storage("config", attach=True)
        root = self.harness.get_filesystem_root(self.container_name)
        patch_generate.return_value = self._mock_home_network_private_key

        self.harness.set_can_connect(container=self.container_name, val=True)
        self.harness.charm._on_install(event=Mock())
        private_key_string = self._get_home_network_private_key_as_hexa_string()

        self.assertEqual((root / "etc/udm/home_network.key").read_text(), private_key_string)

    def test_given_container_cant_connect_when_configure_sdcore_udm_then_status_is_waiting(  # noqa: E501
        self,
    ):
        self.harness.set_can_connect(container=self.container_name, val=False)

        self.harness.charm._configure_sdcore_udm(event=Mock())

        self.assertEqual(
            self.harness.model.unit.status, WaitingStatus("Waiting for container to be ready")
        )

    def test_given_container_can_connect_and_fiveg_nrf_relation_is_not_created_when_configure_sdcore_udm_then_status_is_blocked(  # noqa: E501
        self,
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)

        self.harness.charm._configure_sdcore_udm(event=Mock())

        self.assertEqual(
            self.harness.model.unit.status,
            BlockedStatus("Waiting for `fiveg_nrf` relation to be created"),
        )

    def test_given_certificates_relation_not_created_when_configure_sdcore_udm_then_status_is_blocked(  # noqa E501
        self,
    ):
        self._create_nrf_relation()
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.harness.charm._configure_sdcore_udm(event=Mock())

        self.assertEqual(
            self.harness.model.unit.status,
            BlockedStatus("Waiting for `certificates` relation to be created"),
        )

    @patch("charm.check_output")
    @patch("charms.sdcore_nrf.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    @patch("ops.model.Container.restart")
    def test_given_udm_charm_in_active_status_when_nrf_relation_breaks_then_status_is_blocked(
        self, _, patched_nrf_url, patch_check_output
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)
        root = self.harness.get_filesystem_root(self.container_name)
        certificate = "whatever certificate content"
        private_key_string = self._get_home_network_private_key_as_hexa_string()
        (root / "support/TLS/udm.pem").write_text(certificate)
        (root / "etc/udm/home_network.key").write_text(private_key_string)
        (root / f"etc/udm/{CONFIG_FILE_NAME}").write_text("super different config file content")
        pod_ip = "1.1.1.1"
        patch_check_output.return_value = pod_ip.encode()
        self.harness.set_can_connect(container=self.container_name, val=True)
        patched_nrf_url.return_value = VALID_NRF_URL
        nrf_relation_id = self._create_nrf_relation()
        self._create_certificates_relation()
        self.harness.container_pebble_ready(self.container_name)

        self.harness.remove_relation(nrf_relation_id)

        self.assertEqual(
            self.harness.model.unit.status,
            BlockedStatus("Waiting for fiveg_nrf relation"),
        )

    def test_given_container_can_connect_and_fiveg_nrf_relation_is_created_and_not_available_when_configure_sdcore_udm_then_status_is_waiting(  # noqa: E501
        self,
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.set_can_connect(container=self.container_name, val=True)
        self._create_nrf_relation()
        self._create_certificates_relation()

        self.harness.charm._configure_sdcore_udm(event=Mock())

        self.assertEqual(
            self.harness.model.unit.status,
            WaitingStatus("Waiting for NRF endpoint to be available"),
        )

    @patch("charms.sdcore_nrf.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    def test_given_container_storage_is_not_attached_when_configure_sdcore_udm_then_status_is_waiting(  # noqa: E501
        self,
        patched_nrf_url,
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.set_can_connect(container=self.container_name, val=True)
        patched_nrf_url.return_value = VALID_NRF_URL
        self._create_nrf_relation()
        self._create_certificates_relation()

        self.harness.charm._configure_sdcore_udm(event=Mock())

        self.assertEqual(
            self.harness.model.unit.status, WaitingStatus("Waiting for the storage to be attached")
        )

    @patch("charm.check_output")
    @patch("charms.sdcore_nrf.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    def test_given_home_network_private_key_not_stored_when_configure_sdcore_udm_then_status_is_waiting(  # noqa: E501
        self,
        patched_nrf_url,
        patch_check_output,
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)
        self.harness.set_can_connect(container=self.container_name, val=True)
        patched_nrf_url.return_value = VALID_NRF_URL
        self._create_nrf_relation()
        self._create_certificates_relation()
        pod_ip = "1.1.1.1"
        patch_check_output.return_value = pod_ip.encode()

        self.harness.charm._configure_sdcore_udm(event=Mock())

        self.assertEqual(
            self.harness.model.unit.status,
            WaitingStatus("Waiting for home network private key to be available"),
        )

    @patch("charm.check_output")
    @patch("charms.sdcore_nrf.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    def test_given_config_file_is_not_written_when_configure_sdcore_udm_is_called_then_config_file_is_written_with_expected_content(  # noqa: E501
        self,
        patched_nrf_url,
        patch_check_output,
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)
        root = self.harness.get_filesystem_root(self.container_name)
        certificate = "whatever certificate content"
        private_key_string = "whatever private key"
        (root / "support/TLS/udm.pem").write_text(certificate)
        (root / "etc/udm/home_network.key").write_text(private_key_string)
        pod_ip = "1.1.1.1"
        patch_check_output.return_value = pod_ip.encode()
        self.harness.set_can_connect(container=self.container_name, val=True)
        patched_nrf_url.return_value = VALID_NRF_URL
        self._create_nrf_relation()
        self._create_certificates_relation()
        expected_config_file_content = self._read_file(EXPECTED_CONFIG_FILE_PATH)

        self.harness.charm._configure_sdcore_udm(event=Mock())

        self.assertEqual(
            (root / f"etc/udm/{CONFIG_FILE_NAME}").read_text(),
            expected_config_file_content.strip(),
        )

    @patch("charm.check_output")
    @patch("charms.sdcore_nrf.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    def test_given_config_file_is_written_and_is_not_changed_when_configure_sdcore_udm_is_called_then_config_file_is_not_written(  # noqa: E501
        self, patched_nrf_url, patch_check_output
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)
        root = self.harness.get_filesystem_root(self.container_name)
        certificate = "whatever certificate content"
        private_key_string = "whatever private key"
        (root / "support/TLS/udm.pem").write_text(certificate)
        (root / "etc/udm/home_network.key").write_text(private_key_string)
        (root / f"etc/udm/{CONFIG_FILE_NAME}").write_text(
            self._read_file(EXPECTED_CONFIG_FILE_PATH)
        )
        config_modification_time = (root / f"etc/udm/{CONFIG_FILE_NAME}").stat().st_mtime
        pod_ip = "1.1.1.1"
        patch_check_output.return_value = pod_ip.encode()
        patched_nrf_url.return_value = VALID_NRF_URL
        self._create_nrf_relation()
        self._create_certificates_relation()

        self.harness.charm._configure_sdcore_udm(event=Mock())

        self.assertEqual(
            (root / f"etc/udm/{CONFIG_FILE_NAME}").stat().st_mtime, config_modification_time
        )

    @patch("ops.model.Container.restart")
    @patch("charm.check_output")
    @patch("charms.sdcore_nrf.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    def test_given_config_file_is_written_and_is_not_changed_when_configure_sdcore_udm_is_called_then_after_writting_config_file_service_is_not_restarted(  # noqa: E501
        self, patched_nrf_url, patch_check_output, patch_restart
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)
        root = self.harness.get_filesystem_root(self.container_name)
        certificate = "whatever certificate content"
        private_key_string = "whatever private key"
        (root / "support/TLS/udm.pem").write_text(certificate)
        (root / "etc/udm/home_network.key").write_text(private_key_string)
        (root / f"etc/udm/{CONFIG_FILE_NAME}").write_text(
            self._read_file(EXPECTED_CONFIG_FILE_PATH)
        )
        pod_ip = "1.1.1.1"
        patch_check_output.return_value = pod_ip.encode()
        self._create_nrf_relation()
        self._create_certificates_relation()
        self.harness.set_can_connect(container=self.container_name, val=True)
        patched_nrf_url.return_value = VALID_NRF_URL

        self.harness.charm._configure_sdcore_udm(event=Mock())

        patch_restart.assert_not_called()

    @patch("charm.check_output")
    @patch("charms.sdcore_nrf.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    def test_given_config_file_is_written_and_is_changed_when_configure_sdcore_udm_is_called_then_config_file_is_written(  # noqa: E501
        self,
        patched_nrf_url,
        patch_check_output,
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)
        root = self.harness.get_filesystem_root(self.container_name)
        certificate = "whatever certificate content"
        private_key_string = "whatever private key"
        (root / "support/TLS/udm.pem").write_text(certificate)
        (root / "etc/udm/home_network.key").write_text(private_key_string)
        (root / f"etc/udm/{CONFIG_FILE_NAME}").write_text("super different config file content")
        pod_ip = "1.1.1.1"
        patch_check_output.return_value = pod_ip.encode()
        self.harness.set_can_connect(container=self.container_name, val=True)
        patched_nrf_url.return_value = VALID_NRF_URL
        self._create_nrf_relation()
        self._create_certificates_relation()
        expected_config_file_content = self._read_file(EXPECTED_CONFIG_FILE_PATH)

        self.harness.charm._configure_sdcore_udm(event=Mock())

        self.assertEqual(
            (root / f"etc/udm/{CONFIG_FILE_NAME}").read_text(),
            expected_config_file_content.strip(),
        )

    @patch("ops.model.Container.restart")
    @patch("charm.check_output")
    @patch("charms.sdcore_nrf.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    def test_given_config_file_is_written_and_is_changed_when_configure_sdcore_udm_is_called_then_after_writting_config_file_service_is_restarted(  # noqa: E501
        self,
        patched_nrf_url,
        patch_check_output,
        patch_container_restart,
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)
        root = self.harness.get_filesystem_root(self.container_name)
        certificate = "whatever certificate content"
        private_key_string = "whatever private key"
        (root / "support/TLS/udm.pem").write_text(certificate)
        (root / "etc/udm/home_network.key").write_text(private_key_string)
        (root / f"etc/udm/{CONFIG_FILE_NAME}").write_text("super different config file content")
        pod_ip = "1.1.1.1"
        patch_check_output.return_value = pod_ip.encode()
        self.harness.set_can_connect(container=self.container_name, val=True)
        patched_nrf_url.return_value = VALID_NRF_URL
        self._create_nrf_relation()
        self._create_certificates_relation()

        self.harness.charm._configure_sdcore_udm(event=Mock())

        patch_container_restart.assert_called_with(self.container_name)

    @patch("charm.check_output")
    @patch("charms.sdcore_nrf.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    @patch("ops.model.Container.restart")
    def test_given_config_file_is_written_when_configure_sdcore_udm_is_called_then_pebble_plan_is_applied(  # noqa: E501
        self, _, patched_nrf_url, patch_check_output
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)
        root = self.harness.get_filesystem_root(self.container_name)
        certificate = "whatever certificate content"
        private_key_string = "whatever private key"
        (root / "support/TLS/udm.pem").write_text(certificate)
        (root / "etc/udm/home_network.key").write_text(private_key_string)
        (root / f"etc/udm/{CONFIG_FILE_NAME}").write_text("super different config file content")
        pod_ip = "1.1.1.1"
        patch_check_output.return_value = pod_ip.encode()
        self.harness.set_can_connect(container=self.container_name, val=True)
        patched_nrf_url.return_value = VALID_NRF_URL
        self._create_nrf_relation()
        self._create_certificates_relation()

        self.harness.charm._configure_sdcore_udm(event=Mock())
        expected_plan = {
            "services": {
                self.container_name: {
                    "override": "replace",
                    "startup": "enabled",
                    "command": "/bin/udm --udmcfg /etc/udm/udmcfg.yaml",
                    "environment": {
                        "GRPC_GO_LOG_VERBOSITY_LEVEL": "99",
                        "GRPC_GO_LOG_SEVERITY_LEVEL": "info",
                        "GRPC_TRACE": "all",
                        "GRPC_VERBOSITY": "debug",
                        "POD_IP": "1.1.1.1",
                        "MANAGED_BY_CONFIG_POD": "true",
                    },
                }
            },
        }

        updated_plan = self.harness.get_container_pebble_plan(self.container_name).to_dict()

        self.assertEqual(expected_plan, updated_plan)

    @patch("charm.check_output")
    @patch("charms.sdcore_nrf.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    @patch("ops.Container.push")
    @patch("ops.model.Container.restart")
    def test_given_config_file_is_written_when_configure_sdcore_udm_is_called_then_status_is_active(  # noqa: E501
        self, _, __, patched_nrf_url, patch_check_output
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)
        root = self.harness.get_filesystem_root(self.container_name)
        certificate = "whatever certificate content"
        private_key_string = "whatever private key"
        (root / "support/TLS/udm.pem").write_text(certificate)
        (root / "etc/udm/home_network.key").write_text(private_key_string)
        (root / f"etc/udm/{CONFIG_FILE_NAME}").write_text("super different config file content")
        pod_ip = "1.1.1.1"
        patch_check_output.return_value = pod_ip.encode()
        self.harness.set_can_connect(container=self.container_name, val=True)
        patched_nrf_url.return_value = VALID_NRF_URL
        self._create_nrf_relation()
        self._create_certificates_relation()

        self.harness.container_pebble_ready(self.container_name)

        self.assertEqual(self.harness.model.unit.status, ActiveStatus())

    @patch("charm.check_output")
    @patch("charms.sdcore_nrf.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    def test_given_ip_not_available_when_configure_then_status_is_waiting(
        self, _, patch_check_output
    ):
        self.harness.add_storage(storage_name="config", attach=True)
        patch_check_output.return_value = "".encode()
        self._create_nrf_relation()
        self._create_certificates_relation()

        self.harness.container_pebble_ready(container_name=self.container_name)

        self.assertEqual(
            self.harness.model.unit.status,
            WaitingStatus("Waiting for pod IP address to be available"),
        )

    @patch("charm.check_output")
    @patch("charms.sdcore_nrf.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    def test_given_certificate_is_not_stored_when_configure_sdcore_udm_then_status_is_waiting(  # noqa: E501
        self,
        patch_nrf_url,
        patch_check_output,
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)
        root = self.harness.get_filesystem_root(self.container_name)
        private_key_string = "whatever private key"
        (root / "etc/udm/home_network.key").write_text(private_key_string)
        (root / f"etc/udm/{CONFIG_FILE_NAME}").write_text("super different config file content")
        self.harness.set_can_connect(container=self.container_name, val=True)
        patch_nrf_url.return_value = VALID_NRF_URL
        self._create_nrf_relation()
        self._create_certificates_relation()
        patch_check_output.return_value = b"1.1.1.1"

        self.harness.charm._configure_sdcore_udm(event=Mock())

        self.assertEqual(
            self.harness.model.unit.status, WaitingStatus("Waiting for certificates to be stored")
        )

    @patch("charm.generate_private_key")
    def test_given_can_connect_when_on_certificates_relation_created_then_private_key_is_generated(
        self, patch_generate_private_key
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        root = self.harness.get_filesystem_root(self.container_name)
        private_key = b"whatever key content"
        self.harness.set_can_connect(container=self.container_name, val=True)
        patch_generate_private_key.return_value = private_key

        self.harness.charm._on_certificates_relation_created(event=Mock)

        self.assertEqual((root / "support/TLS/udm.key").read_text(), private_key.decode())

    def test_given_certificates_are_stored_when_on_certificates_relation_broken_then_certificates_are_removed(  # noqa: E501
        self,
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        root = self.harness.get_filesystem_root(self.container_name)
        private_key = "Whatever key content"
        csr = "Whatever CSR content"
        certificate = "Whatever certificate content"
        (root / "support/TLS/udm.key").write_text(private_key)
        (root / "support/TLS/udm.csr").write_text(csr)
        (root / "support/TLS/udm.pem").write_text(certificate)
        self.harness.set_can_connect(container=self.container_name, val=True)

        self.harness.charm._on_certificates_relation_broken(event=Mock)

        with self.assertRaises(FileNotFoundError):
            (root / "support/TLS/udm.key").read_text()
        with self.assertRaises(FileNotFoundError):
            (root / "support/TLS/udm.pem").read_text()
        with self.assertRaises(FileNotFoundError):
            (root / "support/TLS/udm.csr").read_text()

    @patch(
        "charms.tls_certificates_interface.v2.tls_certificates.TLSCertificatesRequiresV2.request_certificate_creation",  # noqa: E501
        new=Mock,
    )
    @patch("charm.generate_csr")
    def test_given_private_key_exists_when_on_certificates_relation_joined_then_csr_is_generated(
        self, patch_generate_csr
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        root = self.harness.get_filesystem_root(self.container_name)
        private_key = "private key content"
        (root / "support/TLS/udm.key").write_text(private_key)
        csr = b"whatever csr content"
        patch_generate_csr.return_value = csr
        self.harness.set_can_connect(container=self.container_name, val=True)

        self.harness.charm._on_certificates_relation_joined(event=Mock)

        self.assertEqual((root / "support/TLS/udm.csr").read_text(), csr.decode())

    @patch(
        "charms.tls_certificates_interface.v2.tls_certificates.TLSCertificatesRequiresV2.request_certificate_creation",  # noqa: E501
    )
    @patch("charm.generate_csr")
    def test_given_private_key_exists_and_cert_not_yet_requested_when_on_certificates_relation_joined_then_cert_is_requested(  # noqa: E501
        self,
        patch_generate_csr,
        patch_request_certificate_creation,
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        root = self.harness.get_filesystem_root(self.container_name)
        private_key = "private key content"
        (root / "support/TLS/udm.key").write_text(private_key)
        csr = b"whatever csr content"
        patch_generate_csr.return_value = csr
        self.harness.set_can_connect(container=self.container_name, val=True)

        self.harness.charm._on_certificates_relation_joined(event=Mock)

        patch_request_certificate_creation.assert_called_with(certificate_signing_request=csr)

    @patch(
        "charms.tls_certificates_interface.v2.tls_certificates.TLSCertificatesRequiresV2.request_certificate_creation",  # noqa: E501
    )
    def test_given_cert_already_stored_when_on_certificates_relation_joined_then_cert_is_not_requested(  # noqa: E501
        self,
        patch_request_certificate_creation,
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        root = self.harness.get_filesystem_root(self.container_name)
        private_key = "private key content"
        certificate = "Whatever certificate content"
        (root / "support/TLS/udm.key").write_text(private_key)
        (root / "support/TLS/udm.pem").write_text(certificate)
        self.harness.set_can_connect(container=self.container_name, val=True)

        self.harness.charm._on_certificates_relation_joined(event=Mock)

        patch_request_certificate_creation.assert_not_called()

    def test_given_csr_matches_stored_one_when_certificate_available_then_certificate_is_pushed(
        self,
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        root = self.harness.get_filesystem_root(self.container_name)
        private_key = "private key content"
        csr = "Whatever CSR content"
        (root / "support/TLS/udm.key").write_text(private_key)
        (root / "support/TLS/udm.csr").write_text(csr)
        certificate = "Whatever certificate content"
        event = Mock()
        event.certificate = certificate
        event.certificate_signing_request = csr
        self.harness.set_can_connect(container=self.container_name, val=True)

        self.harness.charm._on_certificate_available(event=event)

        self.assertEqual((root / "support/TLS/udm.pem").read_text(), certificate)

    def test_given_csr_doesnt_match_stored_one_when_certificate_available_then_certificate_is_not_pushed(  # noqa: E501
        self,
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        root = self.harness.get_filesystem_root(self.container_name)
        csr = "Stored CSR content"
        (root / "support/TLS/udm.csr").write_text(csr)
        certificate = "Whatever certificate content"
        event = Mock()
        event.certificate = certificate
        event.certificate_signing_request = "Relation CSR content (different from stored one)"
        self.harness.set_can_connect(container=self.container_name, val=True)

        self.harness.charm._on_certificate_available(event=event)

        with self.assertRaises(FileNotFoundError):
            (root / "support/TLS/udm.pem").read_text()

    @patch(
        "charms.tls_certificates_interface.v2.tls_certificates.TLSCertificatesRequiresV2.request_certificate_creation",  # noqa: E501
    )
    @patch("charm.generate_csr")
    def test_given_certificate_does_not_match_stored_one_when_certificate_expiring_then_certificate_is_not_requested(  # noqa: E501
        self, patch_generate_csr, patch_request_certificate_creation
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        root = self.harness.get_filesystem_root(self.container_name)
        certificate = "Stored certificate content"
        (root / "support/TLS/udm.pem").write_text(certificate)
        event = Mock()
        event.certificate = "Relation certificate content (different from stored)"
        csr = b"whatever csr content"
        patch_generate_csr.return_value = csr
        self.harness.set_can_connect(container=self.container_name, val=True)

        self.harness.charm._on_certificate_expiring(event=event)

        patch_request_certificate_creation.assert_not_called()

    @patch(
        "charms.tls_certificates_interface.v2.tls_certificates.TLSCertificatesRequiresV2.request_certificate_creation",  # noqa: E501
    )
    @patch("charm.generate_csr")
    def test_given_certificate_matches_stored_one_when_certificate_expiring_then_certificate_is_requested(  # noqa: E501
        self, patch_generate_csr, patch_request_certificate_creation
    ):
        self.harness.add_storage(storage_name="certs", attach=True)
        root = self.harness.get_filesystem_root(self.container_name)
        private_key = "private key content"
        certificate = "whatever certificate content"
        (root / "support/TLS/udm.key").write_text(private_key)
        (root / "support/TLS/udm.pem").write_text(certificate)
        event = Mock()
        event.certificate = certificate
        csr = b"whatever csr content"
        patch_generate_csr.return_value = csr
        self.harness.set_can_connect(container=self.container_name, val=True)

        self.harness.charm._on_certificate_expiring(event=event)

        patch_request_certificate_creation.assert_called_with(certificate_signing_request=csr)

    def test_given_cant_connect_to_workload_when_get_home_network_public_key_action_then_event_fails(  # noqa: E501
        self,
    ):
        self.harness.set_can_connect(container=self.container_name, val=False)

        event = Mock()
        self.harness.charm._on_get_home_network_public_key_action(event=event)

        event.fail.assert_called_with(message="Container is not ready yet.")

    def test_given_home_network_private_key_not_stored_when_get_home_network_public_key_action_then_event_fails(  # noqa: E501
        self,
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        event = Mock()
        self.harness.charm._on_get_home_network_public_key_action(event=event)

        event.fail.assert_called_with(message="Home network private key is not stored yet.")

    def test_given_can_connect_and_key_stored_when_get_home_network_public_key_action_then_public_ip_is_returned(  # noqa: E501
        self,
    ):
        self.harness.add_storage(storage_name="config", attach=True)
        root = self.harness.get_filesystem_root(self.container_name)
        (root / "etc/udm/home_network.key").write_text(
            self._get_home_network_private_key_as_hexa_string()
        )
        self.harness.set_can_connect(container=self.container_name, val=True)
        event = Mock()
        self.harness.charm._on_get_home_network_public_key_action(event=event)
        expected_public_key = self._get_home_network_public_key_as_hexa_string()
        event.set_results.assert_called_with({"public-key": expected_public_key})
