# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

from unittest.mock import PropertyMock, patch

import pytest
from ops import testing

from charm import UDMOperatorCharm


class UDMUnitTestFixtures:
    patcher_sdcore_config_webui_url = patch(
        "charms.sdcore_nms_k8s.v0.sdcore_config.SdcoreConfigRequires.webui_url",
        new_callable=PropertyMock,
    )
    patcher_get_assigned_certificate = patch(
        "charms.tls_certificates_interface.v4.tls_certificates.TLSCertificatesRequiresV4.get_assigned_certificate"
    )
    patcher_nrf_url = patch("charm.NRFRequires.nrf_url", new_callable=PropertyMock)
    patcher_check_output = patch("charm.check_output")
    patcher_generate_x25519_private_key = patch("charm.generate_x25519_private_key")

    @pytest.fixture(autouse=True)
    def setup(self, request):
        self.mock_sdcore_config_webui_url = (
            UDMUnitTestFixtures.patcher_sdcore_config_webui_url.start()
        )
        self.mock_get_assigned_certificate = (
            UDMUnitTestFixtures.patcher_get_assigned_certificate.start()
        )
        self.mock_nrf_url = UDMUnitTestFixtures.patcher_nrf_url.start()
        self.mock_check_output = UDMUnitTestFixtures.patcher_check_output.start()
        self.mock_generate_x25519_private_key = (
            UDMUnitTestFixtures.patcher_generate_x25519_private_key.start()
        )
        yield
        request.addfinalizer(self.teardown)

    @staticmethod
    def teardown() -> None:
        patch.stopall()

    @pytest.fixture(autouse=True)
    def context(self):
        self.ctx = testing.Context(
            charm_type=UDMOperatorCharm,
        )
