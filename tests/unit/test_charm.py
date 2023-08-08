# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
import unittest
from io import StringIO
from unittest.mock import Mock, PropertyMock, patch

import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from ops import testing
from ops.model import ActiveStatus, BlockedStatus, WaitingStatus

from charm import BASE_CONFIG_PATH, CONFIG_FILE_NAME, NRF_RELATION_NAME, UDMOperatorCharm

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

    def _get_metadata(self) -> dict:
        """Reads `metadata.yaml` and returns it as a dictionary.

        Returns:
            dics: metadata.yaml as a dictionary.
        """
        with open("metadata.yaml", "r") as f:
            data = yaml.safe_load(f)
        return data

    def _read_file(self, path: str) -> str:
        """Reads a file an returns as a string.

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

    @patch("ops.Container.push")
    @patch("cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey.generate")
    def test_given_can_connect_when_on_install_then_home_network_key_is_generated_and_pushed_to_container(  # noqa: E501
        self,
        patch_generate,
        patch_push,
    ):
        patch_generate.return_value = self._mock_home_network_private_key

        self.harness.set_can_connect(container=self.container_name, val=True)
        self.harness.charm._on_install(event=Mock())
        private_key_string = self._get_home_network_private_key_as_hexa_string()
        patch_push.assert_called_with(
            path="/etc/udm/home_network.key",
            source=private_key_string,
        )

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

    def test_given_container_can_connect_and_fiveg_nrf_relation_is_created_and_not_available_when_configure_sdcore_udm_then_status_is_waiting(  # noqa: E501
        self,
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        self._create_nrf_relation()

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
        self.harness.set_can_connect(container=self.container_name, val=True)
        patched_nrf_url.return_value = VALID_NRF_URL
        self._create_nrf_relation()
        self.harness.charm._storage_is_attached = Mock(return_value=False)

        self.harness.charm._configure_sdcore_udm(event=Mock())

        self.assertEqual(
            self.harness.model.unit.status, WaitingStatus("Waiting for the storage to be attached")
        )

    @patch("charm.check_output")
    @patch("charms.sdcore_nrf.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    def test_given_home_network_private_key_not_stored_when_configure_sdcore_udm_then_status_is_waiting(  # noqa: E501
        self, patched_nrf_url, patch_check_output
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        patched_nrf_url.return_value = VALID_NRF_URL
        self._create_nrf_relation()
        self.harness.charm._storage_is_attached = Mock(return_value=True)
        pod_ip = "1.1.1.1"
        patch_check_output.return_value = pod_ip.encode()

        self.harness.charm._configure_sdcore_udm(event=Mock())

        self.assertEqual(
            self.harness.model.unit.status,
            WaitingStatus("Waiting for home network private key to be available"),
        )

    @patch("charm.check_output")
    @patch("ops.model.Container.pull")
    @patch("ops.model.Container.exists")
    @patch("ops.Container.push")
    @patch("charms.sdcore_nrf.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    def test_given_config_file_is_not_written_when_configure_sdcore_udm_is_called_then_config_file_is_written_with_expected_content(  # noqa: E501
        self,
        patched_nrf_url,
        patch_push,
        patch_exists,
        patch_pull,
        patch_check_output,
    ):
        pod_ip = "1.1.1.1"
        patch_check_output.return_value = pod_ip.encode()
        patch_pull.side_effect = [
            StringIO("whatever private key"),
            StringIO("whatever private key"),
            StringIO("whatever private key"),
        ]
        self.harness.set_can_connect(container=self.container_name, val=True)
        patched_nrf_url.return_value = VALID_NRF_URL
        self._create_nrf_relation()
        patch_exists.side_effect = [True, True, False, False]
        expected_config_file_content = self._read_file(EXPECTED_CONFIG_FILE_PATH)

        self.harness.charm._configure_sdcore_udm(event=Mock())

        patch_push.assert_called_with(
            path=f"{BASE_CONFIG_PATH}/{CONFIG_FILE_NAME}",
            source=expected_config_file_content.strip(),
        )

    @patch("charm.check_output")
    @patch("ops.model.Container.pull")
    @patch("ops.model.Container.exists")
    @patch("ops.Container.push")
    @patch("charms.sdcore_nrf.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    def test_given_config_file_is_written_and_is_not_changed_when_configure_sdcore_udm_is_called_then_config_file_is_not_written(  # noqa: E501
        self, patched_nrf_url, patch_push, patch_exists, patch_pull, patch_check_output
    ):
        pod_ip = "1.1.1.1"
        patch_check_output.return_value = pod_ip.encode()
        patch_pull.return_value = StringIO(self._read_file(EXPECTED_CONFIG_FILE_PATH))
        patched_nrf_url.return_value = VALID_NRF_URL
        self.harness.charm._storage_is_attached = Mock(return_value=True)
        patch_exists.side_effect = [False, True]
        self._create_nrf_relation()

        self.harness.charm._configure_sdcore_udm(event=Mock())

        patch_push.assert_not_called()

    @patch("ops.model.Container.restart")
    @patch("charm.check_output")
    @patch("ops.model.Container.pull")
    @patch("ops.model.Container.exists")
    @patch("ops.Container.push")
    @patch("charms.sdcore_nrf.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    def test_given_config_file_is_written_and_is_not_changed_when_configure_sdcore_udm_is_called_then_after_writting_config_file_service_is_not_restarted(  # noqa: E501
        self,
        patched_nrf_url,
        patch_push,
        patch_exists,
        patch_pull,
        patch_check_output,
        patch_restart,
    ):
        pod_ip = "1.1.1.1"
        patch_check_output.return_value = pod_ip.encode()
        patch_pull.return_value = StringIO(self._read_file(EXPECTED_CONFIG_FILE_PATH))
        self._create_nrf_relation()
        self.harness.set_can_connect(container=self.container_name, val=True)
        patch_exists.side_effect = [False, True]
        patched_nrf_url.return_value = VALID_NRF_URL
        self.harness.charm._storage_is_attached = Mock(return_value=True)

        self.harness.charm._configure_sdcore_udm(event=Mock())

        patch_restart.assert_not_called()

    @patch("charm.check_output")
    @patch("ops.model.Container.pull")
    @patch("ops.model.Container.exists")
    @patch("ops.Container.push")
    @patch("charms.sdcore_nrf.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    def test_given_config_file_is_written_and_is_changed_when_configure_sdcore_udm_is_called_then_config_file_is_written(  # noqa: E501
        self,
        patched_nrf_url,
        patch_push,
        patch_exists,
        patch_pull,
        patch_check_output,
    ):
        pod_ip = "1.1.1.1"
        self.harness.charm._storage_is_attached = Mock(return_value=True)
        patch_exists.side_effect = [True, False, True, False]
        patch_check_output.return_value = pod_ip.encode()
        patch_pull.side_effect = [
            StringIO("whatever private key"),
            StringIO("super different config file content"),
            StringIO("whatever private key"),
            StringIO("super different config file content"),
        ]
        self.harness.set_can_connect(container=self.container_name, val=True)
        patched_nrf_url.return_value = VALID_NRF_URL
        self._create_nrf_relation()
        expected_config_file_content = self._read_file(EXPECTED_CONFIG_FILE_PATH)

        self.harness.charm._configure_sdcore_udm(event=Mock())

        patch_push.assert_called_with(
            path=f"{BASE_CONFIG_PATH}/{CONFIG_FILE_NAME}",
            source=expected_config_file_content.strip(),
        )

    @patch("ops.model.Container.restart")
    @patch("charm.check_output")
    @patch("ops.model.Container.pull")
    @patch("ops.model.Container.exists")
    @patch("ops.Container.push")
    @patch("charms.sdcore_nrf.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    def test_given_config_file_is_written_and_is_changed_when_configure_sdcore_udm_is_called_then_after_writting_config_file_service_is_restarted(  # noqa: E501
        self,
        patched_nrf_url,
        patch_push,
        patch_exists,
        patch_pull,
        patch_check_output,
        patch_container_restart,
    ):
        pod_ip = "1.1.1.1"
        patch_check_output.return_value = pod_ip.encode()
        patch_pull.return_value = StringIO("super different config file content")
        self.harness.set_can_connect(container=self.container_name, val=True)
        patched_nrf_url.return_value = VALID_NRF_URL
        self._create_nrf_relation()
        self.harness.charm._storage_is_attached = Mock(return_value=True)
        patch_exists.return_value = True

        self.harness.charm._configure_sdcore_udm(event=Mock())

        patch_container_restart.assert_called_with(self.container_name)

    @patch("ops.model.Container.restart")
    @patch("charm.check_output")
    @patch("ops.model.Container.pull")
    @patch("ops.model.Container.exists")
    @patch("ops.Container.push")
    @patch("charms.sdcore_nrf.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    def test_given_config_file_is_written_when_configure_sdcore_udm_is_called_then_pebble_plan_is_applied(  # noqa: E501
        self,
        patched_nrf_url,
        patch_push,
        patch_exists,
        patch_pull,
        patch_check_output,
        patch_container_restart,
    ):
        pod_ip = "1.1.1.1"
        patch_check_output.return_value = pod_ip.encode()
        patch_pull.return_value = StringIO("super different config file content")
        self.harness.set_can_connect(container=self.container_name, val=True)
        patched_nrf_url.return_value = VALID_NRF_URL
        self._create_nrf_relation()
        self.harness.charm._storage_is_attached = Mock(return_value=True)
        patch_exists.return_value = [True, False]

        self.harness.charm._configure_sdcore_udm(event=Mock())
        expected_plan = {
            "services": {
                "udm": {
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

        updated_plan = self.harness.get_container_pebble_plan("udm").to_dict()

        self.assertEqual(expected_plan, updated_plan)

    @patch("ops.model.Container.restart")
    @patch("charm.check_output")
    @patch("ops.model.Container.pull")
    @patch("ops.model.Container.exists")
    @patch("ops.Container.push")
    @patch("charms.sdcore_nrf.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    def test_given_config_file_is_written_when_configure_sdcore_udm_is_called_then_status_is_active(  # noqa: E501
        self,
        patched_nrf_url,
        patch_push,
        patch_exists,
        patch_pull,
        patch_check_output,
        patch_container_restart,
    ):
        pod_ip = "1.1.1.1"
        patch_check_output.return_value = pod_ip.encode()
        patch_pull.return_value = StringIO("super different config file content")
        self.harness.set_can_connect(container=self.container_name, val=True)
        patched_nrf_url.return_value = VALID_NRF_URL
        self._create_nrf_relation()
        self.harness.charm._storage_is_attached = Mock(return_value=True)
        patch_exists.side_effect = [True, False, True, False]

        self.harness.charm._configure_sdcore_udm(event=Mock())

        self.assertEqual(self.harness.model.unit.status, ActiveStatus())

    @patch("charm.check_output")
    @patch("ops.model.Container.pull", new=Mock)
    @patch("ops.model.Container.exists", new=Mock)
    @patch("ops.Container.push", new=Mock)
    @patch("charms.sdcore_nrf.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock)
    def test_given_ip_not_available_when_configure_then_status_is_waiting(
        self,
        patched_nrf_url,
        patch_check_output,
    ):
        patch_check_output.return_value = "".encode()
        self._create_nrf_relation()
        self.harness.charm._storage_is_attached = Mock(return_value=True)

        self.harness.container_pebble_ready(container_name="udm")

        self.assertEqual(
            self.harness.model.unit.status,
            WaitingStatus("Waiting for pod IP address to be available"),
        )

    @patch("charm.generate_private_key")
    @patch("ops.model.Container.push")
    def test_given_can_connect_when_on_certificates_relation_created_then_private_key_is_generated(
        self, patch_push, patch_generate_private_key
    ):
        private_key = b"whatever key content"
        self.harness.set_can_connect(container="udm", val=True)
        patch_generate_private_key.return_value = private_key

        self.harness.charm._on_certificates_relation_created(event=Mock)

        patch_push.assert_called_with(path="/support/TLS/udm.key", source=private_key.decode())

    @patch("ops.model.Container.remove_path")
    @patch("ops.model.Container.exists")
    def test_given_certificates_are_stored_when_on_certificates_relation_broken_then_certificates_are_removed(  # noqa: E501
        self, patch_exists, patch_remove_path
    ):
        patch_exists.return_value = True
        self.harness.set_can_connect(container="udm", val=True)

        self.harness.charm._on_certificates_relation_broken(event=Mock)

        patch_remove_path.assert_any_call(path="/support/TLS/udm.pem")
        patch_remove_path.assert_any_call(path="/support/TLS/udm.key")
        patch_remove_path.assert_any_call(path="/support/TLS/udm.csr")

    @patch(
        "charms.tls_certificates_interface.v2.tls_certificates.TLSCertificatesRequiresV2.request_certificate_creation",  # noqa: E501
        new=Mock,
    )
    @patch("ops.model.Container.push")
    @patch("charm.generate_csr")
    @patch("ops.model.Container.pull")
    @patch("ops.model.Container.exists")
    def test_given_private_key_exists_when_on_certificates_relation_joined_then_csr_is_generated(
        self, patch_exists, patch_pull, patch_generate_csr, patch_push
    ):
        csr = b"whatever csr content"
        patch_generate_csr.return_value = csr
        patch_pull.return_value = StringIO("private key content")
        patch_exists.return_value = True
        self.harness.set_can_connect(container="udm", val=True)

        self.harness.charm._on_certificates_relation_joined(event=Mock)

        patch_push.assert_called_with(path="/support/TLS/udm.csr", source=csr.decode())

    @patch(
        "charms.tls_certificates_interface.v2.tls_certificates.TLSCertificatesRequiresV2.request_certificate_creation",  # noqa: E501
    )
    @patch("ops.model.Container.push", new=Mock)
    @patch("charm.generate_csr")
    @patch("ops.model.Container.pull")
    @patch("ops.model.Container.exists")
    def test_given_private_key_exists_when_on_certificates_relation_joined_then_cert_is_requested(
        self,
        patch_exists,
        patch_pull,
        patch_generate_csr,
        patch_request_certificate_creation,
    ):
        csr = b"whatever csr content"
        patch_generate_csr.return_value = csr
        patch_pull.return_value = StringIO("private key content")
        patch_exists.return_value = True
        self.harness.set_can_connect(container="udm", val=True)

        self.harness.charm._on_certificates_relation_joined(event=Mock)

        patch_request_certificate_creation.assert_called_with(certificate_signing_request=csr)

    @patch("ops.model.Container.pull")
    @patch("ops.model.Container.exists")
    @patch("ops.model.Container.push")
    def test_given_csr_matches_stored_one_when_certificate_available_then_certificate_is_pushed(
        self,
        patch_push,
        patch_exists,
        patch_pull,
    ):
        csr = "Whatever CSR content"
        patch_pull.return_value = StringIO(csr)
        patch_exists.return_value = True
        certificate = "Whatever certificate content"
        event = Mock()
        event.certificate = certificate
        event.certificate_signing_request = csr
        self.harness.set_can_connect(container="udm", val=True)

        self.harness.charm._on_certificate_available(event=event)

        patch_push.assert_called_with(path="/support/TLS/udm.pem", source=certificate)

    @patch("ops.model.Container.pull")
    @patch("ops.model.Container.exists")
    @patch("ops.model.Container.push")
    def test_given_csr_doesnt_match_stored_one_when_certificate_available_then_certificate_is_not_pushed(  # noqa: E501
        self,
        patch_push,
        patch_exists,
        patch_pull,
    ):
        patch_pull.return_value = StringIO("Stored CSR content")
        patch_exists.return_value = True
        certificate = "Whatever certificate content"
        event = Mock()
        event.certificate = certificate
        event.certificate_signing_request = "Relation CSR content (different from stored one)"
        self.harness.set_can_connect(container="udm", val=True)

        self.harness.charm._on_certificate_available(event=event)

        patch_push.assert_not_called()

    @patch(
        "charms.tls_certificates_interface.v2.tls_certificates.TLSCertificatesRequiresV2.request_certificate_creation",  # noqa: E501
    )
    @patch("ops.model.Container.push", new=Mock)
    @patch("charm.generate_csr")
    @patch("ops.model.Container.pull")
    def test_given_certificate_does_not_match_stored_one_when_certificate_expiring_then_certificate_is_not_requested(  # noqa: E501
        self, patch_pull, patch_generate_csr, patch_request_certificate_creation
    ):
        event = Mock()
        patch_pull.return_value = StringIO("Stored certificate content")
        event.certificate = "Relation certificate content (different from stored)"
        csr = b"whatever csr content"
        patch_generate_csr.return_value = csr
        self.harness.set_can_connect(container="udm", val=True)

        self.harness.charm._on_certificate_expiring(event=event)

        patch_request_certificate_creation.assert_not_called()

    @patch(
        "charms.tls_certificates_interface.v2.tls_certificates.TLSCertificatesRequiresV2.request_certificate_creation",  # noqa: E501
    )
    @patch("ops.model.Container.push", new=Mock)
    @patch("charm.generate_csr")
    @patch("ops.model.Container.pull")
    def test_given_certificate_matches_stored_one_when_certificate_expiring_then_certificate_is_requested(  # noqa: E501
        self, patch_pull, patch_generate_csr, patch_request_certificate_creation
    ):
        certificate = "whatever certificate content"
        event = Mock()
        event.certificate = certificate
        patch_pull.return_value = StringIO(certificate)
        csr = b"whatever csr content"
        patch_generate_csr.return_value = csr
        self.harness.set_can_connect(container="udm", val=True)

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

    @patch("ops.model.Container.exists")
    @patch("ops.model.Container.pull")
    def test_given_can_connect_and_key_stored_when_get_home_network_public_key_action_then_public_ip_is_returned(  # noqa: E501
        self, patch_pull, patch_exists
    ):
        patch_pull.return_value = StringIO(self._get_home_network_private_key_as_hexa_string())
        patch_exists.return_value = True
        self.harness.set_can_connect(container=self.container_name, val=True)
        event = Mock()
        self.harness.charm._on_get_home_network_public_key_action(event=event)
        expected_public_key = self._get_home_network_public_key_as_hexa_string()
        event.set_results.assert_called_with({"public-key": expected_public_key})
