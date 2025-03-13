# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


import os
import tempfile

from ops import testing
from ops.pebble import Layer

from tests.unit.certificates_helpers import example_cert_and_key
from tests.unit.fixtures import UDMUnitTestFixtures


class TestCharmConfigure(UDMUnitTestFixtures):
    def test_given_workload_ready_when_configure_then_config_file_is_rendered_and_pushed(  # noqa: E501
        self,
    ):
        with tempfile.TemporaryDirectory() as temp_dir:
            certificates_relation = testing.Relation(
                endpoint="certificates",
                interface="tls-certificates",
            )
            nrf_relation = testing.Relation(
                endpoint="fiveg_nrf",
                interface="fiveg_nrf",
            )
            nms_relation = testing.Relation(
                endpoint="sdcore_config",
                interface="sdcore_config",
            )
            config_mount = testing.Mount(
                location="/etc/udm//",
                source=temp_dir,
            )
            certs_mount = testing.Mount(
                location="/support/TLS",
                source=temp_dir,
            )
            container = testing.Container(
                name="udm",
                can_connect=True,
                mounts={"config": config_mount, "certs": certs_mount},
            )
            state_in = testing.State(
                containers=[container],
                relations=[certificates_relation, nrf_relation, nms_relation],
                leader=True,
                model=testing.Model(name="whatever"),
            )
            self.mock_nrf_url.return_value = "https://nrf:443"
            self.mock_sdcore_config_webui_url.return_value = "sdcore-webui:9876"
            self.mock_check_output.return_value = b"1.1.1.1"
            provider_certificate, private_key = example_cert_and_key(
                relation_id=certificates_relation.id
            )
            self.mock_get_assigned_certificate.return_value = (provider_certificate, private_key)
            self.mock_generate_x25519_private_key.return_value = b"whatever home network key"

            self.ctx.run(self.ctx.on.pebble_ready(container), state_in)

            with open(f"{temp_dir}/udmcfg.yaml", "r") as config_file:
                actual_config = config_file.read()

            with open("tests/unit/expected_udmcfg.yaml", "r") as expected_config_file:
                expected_config = expected_config_file.read()

            assert actual_config.strip() == expected_config.strip()

    def test_given_content_of_config_file_not_changed_when_pebble_ready_then_config_file_is_not_pushed(  # noqa: E501
        self,
    ):
        with tempfile.TemporaryDirectory() as temp_dir:
            certificates_relation = testing.Relation(
                endpoint="certificates",
                interface="tls-certificates",
            )
            nrf_relation = testing.Relation(
                endpoint="fiveg_nrf",
                interface="fiveg_nrf",
            )
            nms_relation = testing.Relation(
                endpoint="sdcore_config",
                interface="sdcore_config",
            )
            config_mount = testing.Mount(
                location="/etc/udm//",
                source=temp_dir,
            )
            certs_mount = testing.Mount(
                location="/support/TLS",
                source=temp_dir,
            )
            container = testing.Container(
                name="udm",
                can_connect=True,
                mounts={"config": config_mount, "certs": certs_mount},
            )
            state_in = testing.State(
                containers=[container],
                relations=[certificates_relation, nrf_relation, nms_relation],
                leader=True,
                model=testing.Model(name="whatever"),
            )
            self.mock_nrf_url.return_value = "https://nrf:443"
            self.mock_sdcore_config_webui_url.return_value = "sdcore-webui:9876"
            self.mock_check_output.return_value = b"1.1.1.1"
            provider_certificate, private_key = example_cert_and_key(
                relation_id=certificates_relation.id
            )
            self.mock_get_assigned_certificate.return_value = (provider_certificate, private_key)
            self.mock_generate_x25519_private_key.return_value = b"whatever home network key"
            with open("tests/unit/expected_udmcfg.yaml", "r") as expected_config_file:
                expected_config = expected_config_file.read()
            with open(f"{temp_dir}/udmcfg.yaml", "w") as config_file:
                config_file.write(expected_config.strip())
            config_modification_time = os.stat(temp_dir + "/udmcfg.yaml").st_mtime

            self.ctx.run(self.ctx.on.pebble_ready(container), state_in)

            with open(f"{temp_dir}/udmcfg.yaml", "r") as config_file:
                actual_config = config_file.read()

            with open("tests/unit/expected_udmcfg.yaml", "r") as expected_config_file:
                expected_config = expected_config_file.read()

            assert actual_config.strip() == expected_config.strip()
            assert os.stat(temp_dir + "/udmcfg.yaml").st_mtime == config_modification_time

    def test_given_given_workload_ready_when_configure_then_pebble_plan_is_applied(  # noqa: E501
        self,
    ):
        with tempfile.TemporaryDirectory() as temp_dir:
            certificates_relation = testing.Relation(
                endpoint="certificates",
                interface="tls-certificates",
            )
            nrf_relation = testing.Relation(
                endpoint="fiveg_nrf",
                interface="fiveg_nrf",
            )
            nms_relation = testing.Relation(
                endpoint="sdcore_config",
                interface="sdcore_config",
            )
            config_mount = testing.Mount(
                location="/etc/udm//",
                source=temp_dir,
            )
            certs_mount = testing.Mount(
                location="/support/TLS",
                source=temp_dir,
            )
            container = testing.Container(
                name="udm",
                can_connect=True,
                mounts={"config": config_mount, "certs": certs_mount},
            )
            state_in = testing.State(
                containers=[container],
                relations=[certificates_relation, nrf_relation, nms_relation],
                leader=True,
            )
            self.mock_nrf_url.return_value = "https://nrf:443"
            self.mock_sdcore_config_webui_url.return_value = "sdcore-webui:9876"
            self.mock_check_output.return_value = b"1.1.1.1"
            provider_certificate, private_key = example_cert_and_key(
                relation_id=certificates_relation.id
            )
            self.mock_get_assigned_certificate.return_value = (provider_certificate, private_key)
            self.mock_generate_x25519_private_key.return_value = b"whatever home network key"

            state_out = self.ctx.run(self.ctx.on.pebble_ready(container), state_in)

            container = state_out.get_container("udm")
            assert container.layers == {
                "udm": Layer(
                    {
                        "summary": "udm layer",
                        "description": "pebble config layer for udm",
                        "services": {
                            "udm": {
                                "startup": "enabled",
                                "override": "replace",
                                "command": "/bin/udm --cfg /etc/udm/udmcfg.yaml",
                                "environment": {
                                    "POD_IP": "1.1.1.1",
                                    "MANAGED_BY_CONFIG_POD": "true",
                                },
                            }
                        },
                    }
                )
            }
