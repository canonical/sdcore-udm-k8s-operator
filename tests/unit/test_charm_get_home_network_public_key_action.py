# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import tempfile

import pytest
from ops import testing
from ops.testing import ActionFailed

from tests.unit.fixtures import UDMUnitTestFixtures


class TestCharmGetHomeNetworkPublicKeyAction(UDMUnitTestFixtures):
    def test_given_cant_connect_when_get_home_network_public_key_action_then_event_fails(self):
        container = testing.Container(
            name="udm",
            can_connect=False,
        )
        state_in = testing.State(
            leader=True,
            containers=[container],
        )

        with pytest.raises(ActionFailed) as exc_info:
            self.ctx.run(self.ctx.on.action("get-home-network-public-key"), state_in)

        assert exc_info.value.message == "Container is not ready yet."

    def test_given_key_not_stored_when_get_home_network_public_key_action_then_event_fails(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            certs_mount = testing.Mount(
                location="/sdcore/certs",
                source=temp_dir,
            )
            container = testing.Container(
                name="udm",
                can_connect=True,
                mounts={"certs": certs_mount},
            )
            state_in = testing.State(
                leader=True,
                containers=[container],
            )

            with pytest.raises(ActionFailed) as exc_info:
                self.ctx.run(self.ctx.on.action("get-home-network-public-key"), state_in)

            assert exc_info.value.message == "Home network private key is not stored yet."

    def test_given_stored_when_get_home_network_public_key_action_then_key_returned(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_mount = testing.Mount(
                location="/sdcore/config/",
                source=temp_dir,
            )
            container = testing.Container(
                name="udm",
                can_connect=True,
                mounts={"config": config_mount},
            )
            state_in = testing.State(
                leader=True,
                containers=[container],
            )
            with open(f"{temp_dir}/home_network.key", "w") as f:
                f.write("f0179dd5c4c8ca35557d21e70f770c247abc38382da1ed6cc42fbf89f3644d65")

            self.ctx.run(self.ctx.on.action("get-home-network-public-key"), state_in)

            assert self.ctx.action_results
            assert self.ctx.action_results["public-key"] is not None
