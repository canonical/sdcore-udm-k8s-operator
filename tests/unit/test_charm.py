# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
import os
from typing import Generator
from unittest.mock import Mock, PropertyMock, patch

import pytest
import yaml
from charm import CONFIG_FILE_NAME, NRF_RELATION_NAME, TLS_RELATION_NAME, UDMOperatorCharm
from charms.tls_certificates_interface.v3.tls_certificates import (
    ProviderCertificate,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from ops import testing
from ops.model import ActiveStatus, BlockedStatus, WaitingStatus

logger = logging.getLogger(__name__)

CERTIFICATE = "whatever certificate content"
CERTIFICATES_LIB = (
    "charms.tls_certificates_interface.v3.tls_certificates.TLSCertificatesRequiresV3"
)
CERTIFICATE_PATH = "support/TLS/udm.pem"
CSR = "Whatever CSR content"
CSR_PATH = "support/TLS/udm.csr"
EXPECTED_CONFIG_FILE_PATH = "tests/unit/expected_udmcfg.yaml"
HOME_NETWORK_KEY = "whatever home network key"
HOME_NETWORK_KEY_PATH = "etc/udm/home_network.key"
POD_IP = b"1.1.1.1"
PRIVATE_KEY = "whatever private key"
PRIVATE_KEY_PATH = "support/TLS/udm.key"
VALID_NRF_URL = "https://nrf:443"
WEBUI_URL = "sdcore-webui:9876"
SDCORE_CONFIG_RELATION_NAME = "sdcore_config"
NMS_APPLICATION_NAME = "sdcore-nms-operator"


class TestCharm:
    patcher_check_output = patch("charm.check_output")
    patcher_container_restart = patch("ops.model.Container.restart")
    patcher_cryptography_generate = patch(
        "cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey.generate"
    )  # noqa E501
    patcher_generate_csr = patch("charm.generate_csr")
    patcher_generate_private_key = patch("charm.generate_private_key")
    patcher_get_assigned_certs = patch(f"{CERTIFICATES_LIB}.get_assigned_certificates")
    patcher_nrf_url = patch(
        "charms.sdcore_nrf_k8s.v0.fiveg_nrf.NRFRequires.nrf_url", new_callable=PropertyMock
    )  # noqa E501
    patcher_request_cert_creation = patch(f"{CERTIFICATES_LIB}.request_certificate_creation")
    patcher_webui_url = patch(
        "charms.sdcore_nms_k8s.v0.sdcore_config.SdcoreConfigRequires.webui_url",
        new_callable=PropertyMock,
    )

    @pytest.fixture()
    def setUp(self):
        self.mock_check_output = TestCharm.patcher_check_output.start()
        self.mock_container_restart = TestCharm.patcher_container_restart.start()
        self.mock_generate_csr = TestCharm.patcher_generate_csr.start()
        self.mock_generate_private_key = TestCharm.patcher_generate_private_key.start()
        self.mock_get_assigned_certs = TestCharm.patcher_get_assigned_certs.start()
        self.mock_nrf_url = TestCharm.patcher_nrf_url.start()
        self.mock_request_certificate_creation = TestCharm.patcher_request_cert_creation.start()
        self.mock_home_network_private_key = X25519PrivateKey.generate()
        self.mock_cryptography_generate = TestCharm.patcher_cryptography_generate.start()
        self.mock_cryptography_generate.return_value = self.mock_home_network_private_key
        self.mock_webui_url = TestCharm.patcher_webui_url.start()
        metadata = self._get_metadata()
        self.container_name = list(metadata["containers"].keys())[0]

    @staticmethod
    def tearDown() -> None:
        patch.stopall()

    @pytest.fixture()
    def mock_default_values(self) -> None:
        self.mock_nrf_url.return_value = VALID_NRF_URL
        self.mock_check_output.return_value = POD_IP
        self.mock_generate_private_key.return_value = PRIVATE_KEY.encode()
        self.mock_generate_csr.return_value = CSR.encode()

    @pytest.fixture(autouse=True)
    def setup_harness(self, setUp, request, mock_default_values):
        self.harness = testing.Harness(UDMOperatorCharm)
        self.harness.set_model_name(name="whatever")
        self.harness.set_leader(is_leader=True)
        self.harness.begin()
        yield self.harness
        self.harness.cleanup()
        request.addfinalizer(self.tearDown)

    @pytest.fixture()
    def add_storage(self) -> None:
        self.harness.add_storage(storage_name="certs", attach=True)
        self.harness.add_storage(storage_name="config", attach=True)

    @staticmethod
    def _get_metadata() -> dict:
        """Read `charmcraft.yaml` and return its content as a dictionary."""
        with open("charmcraft.yaml", "r") as f:
            data = yaml.safe_load(f)
        return data

    @pytest.fixture()
    def sdcore_config_relation_id(self) -> Generator[int, None, None]:
        sdcore_config_relation_id = self.harness.add_relation(
            relation_name=SDCORE_CONFIG_RELATION_NAME,
            remote_app=NMS_APPLICATION_NAME,
        )
        self.harness.add_relation_unit(
            relation_id=sdcore_config_relation_id, remote_unit_name=f"{NMS_APPLICATION_NAME}/0"
        )
        self.harness.update_relation_data(
            relation_id=sdcore_config_relation_id,
            app_or_unit=NMS_APPLICATION_NAME,
            key_values={
                "webui_url": WEBUI_URL,
            },
        )
        yield sdcore_config_relation_id

    @staticmethod
    def _read_file(path: str) -> str:
        """Read a file from a given path and return its content as a string."""
        with open(path, "r") as f:
            content = f.read()
        return content

    @staticmethod
    def _get_provider_certificate():
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = CERTIFICATE
        provider_certificate.csr = CSR
        return provider_certificate

    def _create_nrf_relation(self) -> int:
        """Create NRF relation and return its relation id."""
        relation_id = self.harness.add_relation(
            relation_name=NRF_RELATION_NAME, remote_app="nrf-operator"
        )
        self.harness.add_relation_unit(relation_id=relation_id, remote_unit_name="nrf-operator/0")
        return relation_id

    def _create_certificates_relation(self):
        relation_id = self.harness.add_relation(
            relation_name=TLS_RELATION_NAME, remote_app="tls-certificates-operator"
        )
        self.harness.add_relation_unit(
            relation_id=relation_id, remote_unit_name="tls-certificates-operator/0"
        )

    def _write_keys_csr_and_certificate_files(self) -> None:
        root = self.harness.get_filesystem_root(self.container_name)
        (root / PRIVATE_KEY_PATH).write_text(PRIVATE_KEY)
        (root / HOME_NETWORK_KEY_PATH).write_text(HOME_NETWORK_KEY)
        (root / CERTIFICATE_PATH).write_text(CERTIFICATE)
        (root / CSR_PATH).write_text(CSR)

    def _get_home_network_private_key_as_hexadecimal_string(self) -> str:
        private_bytes = self.mock_home_network_private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return private_bytes.hex()

    def _get_home_network_public_key_as_hexadecimal_string(self) -> str:
        public_key = self.mock_home_network_private_key.public_key()
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        return public_bytes.hex()

    def test_given_container_cant_connect_when_configure_sdcore_udm_then_status_is_waiting(self):
        self.harness.set_can_connect(container=self.container_name, val=False)

        self.harness.charm._configure_sdcore_udm(event=Mock())
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == WaitingStatus("Waiting for container to be ready")

    def test_given_container_can_connect_and_fiveg_nrf_relation_is_not_created_when_configure_sdcore_udm_then_status_is_blocked(  # noqa: E501
        self, sdcore_config_relation_id
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        self._create_certificates_relation()
        self.harness.charm._configure_sdcore_udm(event=Mock())
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == BlockedStatus("Waiting for fiveg_nrf relation(s)")

    def test_given_certificates_relation_not_created_when_configure_sdcore_udm_then_status_is_blocked(  # noqa E501
        self, sdcore_config_relation_id
    ):
        self._create_nrf_relation()
        self.harness.set_can_connect(container=self.container_name, val=True)

        self.harness.charm._configure_sdcore_udm(event=Mock())
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == BlockedStatus(
            "Waiting for certificates relation(s)"
        )

    def test_given_sdcore_config_relation_not_created_when_configure_sdcore_udm_then_status_is_blocked(  # noqa E501
        self,
    ):
        self._create_nrf_relation()
        self._create_certificates_relation()
        self.harness.set_can_connect(container=self.container_name, val=True)

        self.harness.charm._configure_sdcore_udm(event=Mock())
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == BlockedStatus(
            "Waiting for sdcore_config relation(s)"
        )

    def test_given_udm_charm_in_active_status_when_nrf_relation_breaks_then_status_is_blocked(
        self, add_storage, sdcore_config_relation_id
    ):
        self._write_keys_csr_and_certificate_files()
        root = self.harness.get_filesystem_root(self.container_name)
        (root / f"etc/udm/{CONFIG_FILE_NAME}").write_text("super different config file content")
        self._create_certificates_relation()
        nrf_relation_id = self._create_nrf_relation()
        self.harness.container_pebble_ready(self.container_name)

        self.harness.remove_relation(nrf_relation_id)
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == BlockedStatus("Waiting for fiveg_nrf relation(s)")

    def test_given_udm_charm_in_active_status_when_sdcore_config_relation_breaks_then_status_is_blocked(  # noqa E501
        self, add_storage, sdcore_config_relation_id
    ):
        self._write_keys_csr_and_certificate_files()
        root = self.harness.get_filesystem_root(self.container_name)
        (root / f"etc/udm/{CONFIG_FILE_NAME}").write_text("super different config file content")
        self._create_certificates_relation()
        self._create_nrf_relation()
        self.harness.container_pebble_ready(self.container_name)

        self.harness.remove_relation(sdcore_config_relation_id)
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == BlockedStatus(
            "Waiting for sdcore_config relation(s)"
        )

    def test_given_container_can_connect_and_fiveg_nrf_relation_is_created_and_not_available_when_configure_sdcore_udm_then_status_is_waiting(  # noqa: E501
        self, add_storage, sdcore_config_relation_id
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.mock_nrf_url.return_value = None
        self._create_nrf_relation()
        self._create_certificates_relation()

        self.harness.charm._configure_sdcore_udm(event=Mock())
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == WaitingStatus(
            "Waiting for NRF endpoint to be available"
        )

    def test_given_container_can_connect_and_sdcore_config_relation_is_created_and_not_available_when_configure_sdcore_udm_then_status_is_waiting(  # noqa: E501
        self, add_storage, sdcore_config_relation_id
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.mock_nrf_url.return_value = VALID_NRF_URL
        self.mock_webui_url.return_value = ""
        self._create_nrf_relation()
        self._create_certificates_relation()

        self.harness.charm._configure_sdcore_udm(event=Mock())
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == WaitingStatus(
            "Waiting for Webui data to be available"
        )

    @pytest.mark.parametrize(
        "storage_name",
        [
            "certs",
            "config",
        ],
    )
    def test_given_storage_is_not_attached_when_configure_sdcore_udm_then_status_is_waiting(
        self, storage_name, sdcore_config_relation_id
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.harness.add_storage(storage_name=storage_name, attach=True)
        self._create_nrf_relation()
        self._create_certificates_relation()

        self.harness.charm._configure_sdcore_udm(event=Mock())
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == WaitingStatus(
            "Waiting for the storage to be attached"
        )

    def test_given_home_network_private_key_not_stored_when_configure_sdcore_udm_then_home_network_private_key_is_generated(  # noqa: E501
        self, add_storage, sdcore_config_relation_id
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        self.mock_generate_private_key.return_value = PRIVATE_KEY.encode()
        self.mock_generate_csr.return_value = CSR.encode()
        home_network_private_key = self._get_home_network_private_key_as_hexadecimal_string()
        root = self.harness.get_filesystem_root(self.container_name)
        self._create_nrf_relation()
        self._create_certificates_relation()

        self.harness.charm._configure_sdcore_udm(event=Mock())

        assert (root / HOME_NETWORK_KEY_PATH).read_text() == home_network_private_key

    def test_given_home_network_private_key_stored_when_configure_sdcore_udm_then_home_network_private_key_is_not_generated(  # noqa: E501
        self, add_storage, sdcore_config_relation_id
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        root = self.harness.get_filesystem_root(self.container_name)
        (root / HOME_NETWORK_KEY_PATH).write_text(HOME_NETWORK_KEY)
        config_modification_time = (root / HOME_NETWORK_KEY_PATH).stat().st_mtime
        self._create_nrf_relation()
        self._create_certificates_relation()

        self.harness.charm._configure_sdcore_udm(event=Mock())

        assert (root / HOME_NETWORK_KEY_PATH).stat().st_mtime == config_modification_time

    def test_given_config_file_is_not_written_when_configure_sdcore_udm_is_called_then_config_file_is_written_with_expected_content(  # noqa: E501
        self, add_storage, sdcore_config_relation_id
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        self._write_keys_csr_and_certificate_files()
        self._create_nrf_relation()
        self._create_certificates_relation()
        self.mock_webui_url.return_value = WEBUI_URL
        expected_config_file_content = self._read_file(EXPECTED_CONFIG_FILE_PATH).strip()
        self.mock_get_assigned_certs.return_value = [self._get_provider_certificate()]

        self.harness.charm._configure_sdcore_udm(event=Mock())

        root = self.harness.get_filesystem_root(self.container_name)
        assert (root / f"etc/udm/{CONFIG_FILE_NAME}").read_text() == expected_config_file_content

    def test_given_config_file_is_written_and_is_not_changed_when_configure_sdcore_udm_is_called_then_config_file_is_not_written(  # noqa: E501
        self, add_storage, sdcore_config_relation_id
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        self._write_keys_csr_and_certificate_files()
        root = self.harness.get_filesystem_root(self.container_name)
        (root / f"etc/udm/{CONFIG_FILE_NAME}").write_text(
            self._read_file(EXPECTED_CONFIG_FILE_PATH)
        )
        config_modification_time = (root / f"etc/udm/{CONFIG_FILE_NAME}").stat().st_mtime
        self._create_nrf_relation()
        self._create_certificates_relation()
        self.mock_webui_url.return_value = WEBUI_URL
        self.mock_get_assigned_certs.return_value = [self._get_provider_certificate()]

        self.harness.charm._configure_sdcore_udm(event=Mock())

        assert (root / f"etc/udm/{CONFIG_FILE_NAME}").stat().st_mtime == config_modification_time

    def test_given_config_file_is_written_and_is_not_changed_when_configure_sdcore_udm_is_called_then_after_writting_config_file_service_is_not_restarted(  # noqa: E501
        self, add_storage, sdcore_config_relation_id
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        self._write_keys_csr_and_certificate_files()
        root = self.harness.get_filesystem_root(self.container_name)
        (root / f"etc/udm/{CONFIG_FILE_NAME}").write_text(
            self._read_file(EXPECTED_CONFIG_FILE_PATH)
        )
        self._create_nrf_relation()
        self._create_certificates_relation()
        self.mock_webui_url.return_value = WEBUI_URL
        self.mock_get_assigned_certs.return_value = [self._get_provider_certificate()]

        self.harness.charm._configure_sdcore_udm(event=Mock())

        self.mock_container_restart.assert_not_called()

    def test_given_config_file_is_written_and_is_changed_when_configure_sdcore_udm_is_called_then_config_file_is_written(  # noqa: E501
        self, add_storage, sdcore_config_relation_id
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        self._write_keys_csr_and_certificate_files()
        root = self.harness.get_filesystem_root(self.container_name)
        (root / f"etc/udm/{CONFIG_FILE_NAME}").write_text("super different config file content")
        self._create_nrf_relation()
        self._create_certificates_relation()
        self.mock_webui_url.return_value = WEBUI_URL
        expected_config_file_content = self._read_file(EXPECTED_CONFIG_FILE_PATH).strip()
        self.mock_get_assigned_certs.return_value = [self._get_provider_certificate()]

        self.harness.charm._configure_sdcore_udm(event=Mock())

        assert (root / f"etc/udm/{CONFIG_FILE_NAME}").read_text() == expected_config_file_content

    def test_given_config_file_is_written_and_is_changed_when_configure_sdcore_udm_is_called_then_after_writting_config_file_service_is_restarted(  # noqa: E501
        self, add_storage, sdcore_config_relation_id
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        self._write_keys_csr_and_certificate_files()
        root = self.harness.get_filesystem_root(self.container_name)
        (root / f"etc/udm/{CONFIG_FILE_NAME}").write_text("super different config file content")
        self._create_nrf_relation()
        self._create_certificates_relation()
        self.mock_get_assigned_certs.return_value = [self._get_provider_certificate()]

        self.harness.charm._configure_sdcore_udm(event=Mock())

        self.mock_container_restart.assert_called_with(self.container_name)

    def test_given_config_file_is_written_and_webui_data_is_changed_when_configure_sdcore_udm_is_called_then_after_writting_config_file_service_is_restarted(  # noqa: E501
        self, add_storage, sdcore_config_relation_id
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        self._write_keys_csr_and_certificate_files()
        root = self.harness.get_filesystem_root(self.container_name)
        (root / f"etc/udm/{CONFIG_FILE_NAME}").write_text(
            self._read_file(EXPECTED_CONFIG_FILE_PATH)
        )
        self._create_nrf_relation()
        self._create_certificates_relation()
        self.mock_webui_url.return_value = "mywebui:9870"
        self.mock_get_assigned_certs.return_value = [self._get_provider_certificate()]

        self.harness.charm._configure_sdcore_udm(event=Mock())

        self.mock_container_restart.assert_called_with(self.container_name)

    def test_given_config_file_is_written_when_configure_sdcore_udm_is_called_then_pebble_plan_is_applied(  # noqa: E501
        self, add_storage, sdcore_config_relation_id
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        self._write_keys_csr_and_certificate_files()
        root = self.harness.get_filesystem_root(self.container_name)
        (root / f"etc/udm/{CONFIG_FILE_NAME}").write_text("super different config file content")
        self._create_nrf_relation()
        self._create_certificates_relation()
        self.mock_get_assigned_certs.return_value = [self._get_provider_certificate()]

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
        assert expected_plan == updated_plan

    def test_given_config_file_written_when_configure_sdcore_udm_is_called_then_status_is_active(
        self, add_storage, sdcore_config_relation_id
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        self._write_keys_csr_and_certificate_files()
        root = self.harness.get_filesystem_root(self.container_name)
        (root / f"etc/udm/{CONFIG_FILE_NAME}").write_text("super different config file content")
        self.mock_get_assigned_certs.return_value = [self._get_provider_certificate()]
        self._create_nrf_relation()
        self._create_certificates_relation()
        self.mock_webui_url.return_value = WEBUI_URL

        self.harness.container_pebble_ready(self.container_name)
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == ActiveStatus()

    def test_given_ip_not_available_when_configure_then_status_is_waiting(
        self,
        add_storage,
        sdcore_config_relation_id,
    ):
        self.mock_check_output.return_value = "".encode()
        self._create_nrf_relation()
        self._create_certificates_relation()

        self.harness.container_pebble_ready(container_name=self.container_name)
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == WaitingStatus(
            "Waiting for pod IP address to be available"
        )

    def test_given_certificate_not_stored_when_configure_sdcore_udm_then_status_is_waiting(
        self, add_storage, sdcore_config_relation_id
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        root = self.harness.get_filesystem_root(self.container_name)
        (root / HOME_NETWORK_KEY_PATH).write_text(HOME_NETWORK_KEY)
        self._create_nrf_relation()
        self._create_certificates_relation()

        self.harness.charm._configure_sdcore_udm(event=Mock())
        self.harness.evaluate_status()

        assert self.harness.model.unit.status == WaitingStatus(
            "Waiting for certificates to be stored"
        )

    def test_given_can_connect_when_on_certificates_relation_created_then_private_key_is_generated(
        self, add_storage, sdcore_config_relation_id
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        root = self.harness.get_filesystem_root(self.container_name)
        (root / HOME_NETWORK_KEY_PATH).write_text(HOME_NETWORK_KEY)
        self.mock_generate_private_key.return_value = PRIVATE_KEY.encode()
        self._create_nrf_relation()

        self._create_certificates_relation()

        assert (root / PRIVATE_KEY_PATH).read_text() == PRIVATE_KEY

    def test_given_certificates_are_stored_when_on_certificates_relation_broken_then_certificates_are_removed(  # noqa: E501
        self, add_storage, sdcore_config_relation_id
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        self._write_keys_csr_and_certificate_files()

        self.harness.charm._on_certificates_relation_broken(event=Mock)

        root = self.harness.get_filesystem_root(self.container_name)
        with pytest.raises(FileNotFoundError):
            (root / PRIVATE_KEY_PATH).read_text()
        with pytest.raises(FileNotFoundError):
            (root / CERTIFICATE_PATH).read_text()
        with pytest.raises(FileNotFoundError):
            (root / CSR_PATH).read_text()

    def test_given_cannot_connect_on_certificates_relation_broken_then_certificates_are_not_removed(  # noqa: E501
        self, add_storage, sdcore_config_relation_id
    ):
        self.harness.set_can_connect(container=self.container_name, val=False)
        self._write_keys_csr_and_certificate_files()

        self.harness.charm._on_certificates_relation_broken(event=Mock())

        root = self.harness.get_filesystem_root(self.container_name)
        container_private_key = (root / PRIVATE_KEY_PATH).read_text()
        container_certificate = (root / CERTIFICATE_PATH).read_text()
        container_csr = (root / CSR_PATH).read_text()
        assert container_private_key == PRIVATE_KEY
        assert container_certificate == CERTIFICATE
        assert container_csr == CSR

    def test_given_certificates_not_stored_when_on_certificates_relation_broken_then_certificates_dont_exist(  # noqa: E501
        self, add_storage, sdcore_config_relation_id
    ):
        root = self.harness.get_filesystem_root(self.container_name)
        self.harness.set_can_connect(container=self.container_name, val=True)

        self.harness.charm._on_certificates_relation_broken(event=Mock)

        with pytest.raises(FileNotFoundError):
            (root / PRIVATE_KEY_PATH).read_text()
        with pytest.raises(FileNotFoundError):
            (root / CERTIFICATE_PATH).read_text()
        with pytest.raises(FileNotFoundError):
            (root / CSR_PATH).read_text()

    def test_given_private_key_exists_when_on_certificates_relation_joined_then_csr_is_generated(
        self, add_storage, sdcore_config_relation_id
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        root = self.harness.get_filesystem_root(self.container_name)
        (root / HOME_NETWORK_KEY_PATH).write_text(HOME_NETWORK_KEY)
        (root / PRIVATE_KEY_PATH).write_text(PRIVATE_KEY)
        self.mock_generate_csr.return_value = CSR.encode()
        self._create_nrf_relation()

        self._create_certificates_relation()

        assert (root / CSR_PATH).read_text() == CSR

    def test_given_private_key_exists_and_cert_not_yet_requested_when_on_certificates_relation_joined_then_cert_is_requested(  # noqa: E501
        self, add_storage, sdcore_config_relation_id
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        root = self.harness.get_filesystem_root(self.container_name)
        (root / HOME_NETWORK_KEY_PATH).write_text(HOME_NETWORK_KEY)
        (root / PRIVATE_KEY_PATH).write_text(PRIVATE_KEY)
        self.mock_generate_csr.return_value = CSR.encode()
        self._create_nrf_relation()

        self._create_certificates_relation()

        self.mock_request_certificate_creation.assert_called_with(
            certificate_signing_request=CSR.encode()
        )

    def test_given_cert_already_stored_when_on_certificates_relation_joined_then_cert_is_not_requested(  # noqa: E501
        self, add_storage, sdcore_config_relation_id
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        root = self.harness.get_filesystem_root(self.container_name)
        (root / HOME_NETWORK_KEY_PATH).write_text(HOME_NETWORK_KEY)
        (root / CSR_PATH).write_text(CSR)
        (root / PRIVATE_KEY_PATH).write_text(PRIVATE_KEY)
        self._create_nrf_relation()

        self._create_certificates_relation()

        self.mock_request_certificate_creation.assert_not_called()

    def test_given_csr_matches_stored_one_when_certificate_available_then_certificate_is_pushed(
        self, add_storage, sdcore_config_relation_id
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        root = self.harness.get_filesystem_root(self.container_name)
        (root / HOME_NETWORK_KEY_PATH).write_text(HOME_NETWORK_KEY)
        (root / PRIVATE_KEY_PATH).write_text(PRIVATE_KEY)
        (root / CSR_PATH).write_text(CSR)
        self._create_nrf_relation()
        self._create_certificates_relation()
        self.mock_get_assigned_certs.return_value = [self._get_provider_certificate()]

        self.harness.container_pebble_ready("udm")

        assert (root / CERTIFICATE_PATH).read_text() == CERTIFICATE

    def test_given_csr_doesnt_match_stored_one_when_certificate_available_then_certificate_is_not_pushed(  # noqa: E501
        self, add_storage, sdcore_config_relation_id
    ):
        self.harness.set_can_connect(container=self.container_name, val=True)
        root = self.harness.get_filesystem_root(self.container_name)
        (root / HOME_NETWORK_KEY_PATH).write_text(HOME_NETWORK_KEY)
        (root / CSR_PATH).write_text(CSR)
        self._create_nrf_relation()
        self._create_certificates_relation()
        provider_certificate = Mock(ProviderCertificate)
        provider_certificate.certificate = CERTIFICATE
        provider_certificate.csr = "Relation CSR content (different from stored one)"
        self.mock_get_assigned_certs.return_value = [provider_certificate]

        self.harness.container_pebble_ready("udm")

        with pytest.raises(FileNotFoundError):
            (root / CERTIFICATE_PATH).read_text()

    def test_given_certificate_does_not_match_stored_one_when_certificate_expiring_then_certificate_is_not_requested(  # noqa: E501
        self, add_storage, sdcore_config_relation_id
    ):
        root = self.harness.get_filesystem_root(self.container_name)
        (root / CERTIFICATE_PATH).write_text(CERTIFICATE)
        event = Mock()
        event.certificate = "Relation certificate content (different from stored)"
        self.mock_generate_csr.return_value = CSR.encode()
        self.harness.set_can_connect(container=self.container_name, val=True)

        self.harness.charm._on_certificate_expiring(event=event)

        self.mock_request_certificate_creation.assert_not_called()

    def test_given_certificate_matches_stored_one_when_certificate_expiring_then_certificate_is_requested(  # noqa: E501
        self, add_storage, sdcore_config_relation_id
    ):
        root = self.harness.get_filesystem_root(self.container_name)
        (root / PRIVATE_KEY_PATH).write_text(PRIVATE_KEY)
        (root / CERTIFICATE_PATH).write_text(CERTIFICATE)
        event = Mock()
        event.certificate = CERTIFICATE
        self.mock_generate_csr.return_value = CSR.encode()
        self.harness.set_can_connect(container=self.container_name, val=True)

        self.harness.charm._on_certificate_expiring(event=event)

        self.mock_request_certificate_creation.assert_called_with(
            certificate_signing_request=CSR.encode()
        )

    def test_given_cannot_connect_when_certificate_expiring_then_certificate_is_not_requested(
        self, add_storage, sdcore_config_relation_id
    ):
        root = self.harness.get_filesystem_root(self.container_name)
        (root / PRIVATE_KEY_PATH).write_text(PRIVATE_KEY)
        (root / CERTIFICATE_PATH).write_text(CERTIFICATE)
        event = Mock()
        event.certificate = CERTIFICATE
        self.harness.set_can_connect(container=self.container_name, val=False)

        self.harness.charm._on_certificate_expiring(event=event)

        self.mock_request_certificate_creation.assert_not_called()

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
        self, add_storage, sdcore_config_relation_id
    ):
        root = self.harness.get_filesystem_root(self.container_name)
        (root / HOME_NETWORK_KEY_PATH).write_text(
            self._get_home_network_private_key_as_hexadecimal_string()
        )
        self.harness.set_can_connect(container=self.container_name, val=True)

        event = Mock()
        self.harness.charm._on_get_home_network_public_key_action(event=event)

        expected_public_key = self._get_home_network_public_key_as_hexadecimal_string()
        event.set_results.assert_called_with({"public-key": expected_public_key})

    def test_given_not_leader_when_collect_status_then_status_is_blocked(self):
        self.harness.set_leader(is_leader=False)

        self.harness.evaluate_status()

        assert self.harness.model.unit.status == BlockedStatus(
            "Scaling is not implemented for this charm"
        )

    def test_given_no_workload_version_file_when_container_can_connect_then_workload_version_not_set(  # noqa: E501
        self,
    ):
        self.harness.container_pebble_ready(container_name=self.container_name)
        self.harness.evaluate_status()
        version = self.harness.get_workload_version()
        assert version == ""

    def test_given_workload_version_file_when_container_can_connect_then_workload_version_set(
        self,
    ):
        expected_version = "1.2.3"
        root = self.harness.get_filesystem_root(self.container_name)
        os.mkdir(f"{root}/etc")
        (root / "etc/workload-version").write_text(expected_version)
        self.harness.container_pebble_ready(container_name=self.container_name)
        self.harness.evaluate_status()
        version = self.harness.get_workload_version()
        assert version == expected_version
