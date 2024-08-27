# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


import tempfile

import scenario

from tests.unit.fixtures import UDMUnitTestFixtures


class TestCharmGetHomeNetworkPublicKeyAction(UDMUnitTestFixtures):
    def test_given_cant_connect_when_get_home_network_public_key_action_then_event_fails(self):
        container = scenario.Container(
            name="udm",
            can_connect=False,
        )
        state_in = scenario.State(
            leader=True,
            containers=[container],
        )
        action = scenario.Action(
            name="get-home-network-public-key",
        )

        action_output = self.ctx.run_action(action, state_in)

        assert action_output.success is False
        assert action_output.failure == "Container is not ready yet."

    def test_given_key_not_stored_when_get_home_network_public_key_action_then_event_fails(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            certs_mount = scenario.Mount(
                location="/support/TLS",
                src=temp_dir,
            )
            container = scenario.Container(
                name="udm",
                can_connect=True,
                mounts={"certs": certs_mount},
            )
            state_in = scenario.State(
                leader=True,
                containers=[container],
            )
            action = scenario.Action(
                name="get-home-network-public-key",
            )

            action_output = self.ctx.run_action(action, state_in)

            assert action_output.success is False
            assert action_output.failure == "Home network private key is not stored yet."

    def test_given_stored_when_get_home_network_public_key_action_then_key_returned(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_mount = scenario.Mount(
                location="/etc/udm/",
                src=temp_dir,
            )
            container = scenario.Container(
                name="udm",
                can_connect=True,
                mounts={"config": config_mount},
            )
            state_in = scenario.State(
                leader=True,
                containers=[container],
            )
            action = scenario.Action(
                name="get-home-network-public-key",
            )
            with open(f"{temp_dir}/home_network.key", "w") as f:
                f.write("f0179dd5c4c8ca35557d21e70f770c247abc38382da1ed6cc42fbf89f3644d65")

            action_output = self.ctx.run_action(action, state_in)

            assert action_output.success is True
            assert action_output.results
            assert "public-key" in action_output.results
