#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.


import logging
from collections import Counter
from pathlib import Path

import pytest
import yaml
from juju.application import Application
from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./charmcraft.yaml").read_text())
APPLICATION_NAME = METADATA["name"]
NRF_APP_NAME = "sdcore-nrf-k8s"
NRF_APP_CHANNEL = "1.6/edge"
DATABASE_APP_NAME = "mongodb-k8s"
DATABASE_APP_CHANNEL = "6/stable"
TLS_PROVIDER_APP_NAME = "self-signed-certificates"
TLS_PROVIDER_APP_CHANNEL = "latest/stable"
GRAFANA_AGENT_APP_NAME = "grafana-agent-k8s"
GRAFANA_AGENT_APP_CHANNEL = "1/stable"
NMS_CHARM_NAME = "sdcore-nms-k8s"
NMS_CHARM_CHANNEL = "1.6/edge"
SDCORE_CHARMS_BASE = "ubuntu@24.04"
TIMEOUT = 1000


async def _deploy_database(ops_test: OpsTest):
    """Deploy a MongoDB."""
    assert ops_test.model
    await ops_test.model.deploy(
        DATABASE_APP_NAME,
        application_name=DATABASE_APP_NAME,
        channel=DATABASE_APP_CHANNEL,
        trust=True,
    )


async def _deploy_nrf(ops_test: OpsTest):
    assert ops_test.model
    await ops_test.model.deploy(
        NRF_APP_NAME,
        application_name=NRF_APP_NAME,
        channel=NRF_APP_CHANNEL,
        trust=True,
        base=SDCORE_CHARMS_BASE,
    )
    await ops_test.model.integrate(relation1=NRF_APP_NAME, relation2=TLS_PROVIDER_APP_NAME)
    await ops_test.model.integrate(relation1=NRF_APP_NAME, relation2=NMS_CHARM_NAME)
    await ops_test.model.integrate(relation1=NRF_APP_NAME, relation2=DATABASE_APP_NAME)


async def _deploy_nms(ops_test: OpsTest):
    assert ops_test.model
    await ops_test.model.deploy(
        NMS_CHARM_NAME,
        application_name=NMS_CHARM_NAME,
        channel=NMS_CHARM_CHANNEL,
        base=SDCORE_CHARMS_BASE,
    )
    await ops_test.model.integrate(
        relation1=f"{NMS_CHARM_NAME}:common_database", relation2=DATABASE_APP_NAME
    )
    await ops_test.model.integrate(
        relation1=f"{NMS_CHARM_NAME}:auth_database", relation2=DATABASE_APP_NAME
    )
    await ops_test.model.integrate(
        relation1=f"{NMS_CHARM_NAME}:webui_database", relation2=DATABASE_APP_NAME
    )
    await ops_test.model.integrate(relation1=NMS_CHARM_NAME, relation2=TLS_PROVIDER_APP_NAME)


async def _deploy_grafana_agent(ops_test: OpsTest):
    """Deploy a Grafana agent."""
    assert ops_test.model
    await ops_test.model.deploy(
        GRAFANA_AGENT_APP_NAME,
        application_name=GRAFANA_AGENT_APP_NAME,
        channel=GRAFANA_AGENT_APP_CHANNEL,
    )


async def _deploy_tls_provider(ops_test: OpsTest):
    """Deploy a TLS provider."""
    assert ops_test.model
    await ops_test.model.deploy(
        TLS_PROVIDER_APP_NAME,
        application_name=TLS_PROVIDER_APP_NAME,
        channel=TLS_PROVIDER_APP_CHANNEL,
    )


@pytest.fixture(scope="module")
async def deploy(ops_test: OpsTest, request):
    """Deploy necessary components."""
    assert ops_test.model
    charm = Path(request.config.getoption("--charm_path")).resolve()
    resources = {
        "udm-image": METADATA["resources"]["udm-image"]["upstream-source"],
    }
    await ops_test.model.deploy(
        charm,
        resources=resources,
        application_name=APPLICATION_NAME,
        trust=True,
    )
    await _deploy_database(ops_test)
    await _deploy_tls_provider(ops_test)
    await _deploy_grafana_agent(ops_test)
    await _deploy_nms(ops_test)
    await _deploy_nrf(ops_test)


@pytest.mark.abort_on_fail
async def test_given_charm_is_built_when_deployed_then_status_is_blocked(
    ops_test: OpsTest, deploy
):
    assert ops_test.model
    await ops_test.model.wait_for_idle(
        apps=[APPLICATION_NAME],
        status="blocked",
        timeout=TIMEOUT,
    )


@pytest.mark.abort_on_fail
async def test_relate_and_wait_for_active_status(ops_test: OpsTest, deploy):
    assert ops_test.model
    await ops_test.model.integrate(
        relation1=f"{APPLICATION_NAME}:fiveg_nrf", relation2=NRF_APP_NAME
    )
    await ops_test.model.integrate(relation1=APPLICATION_NAME, relation2=TLS_PROVIDER_APP_NAME)
    await ops_test.model.integrate(
        relation1=f"{APPLICATION_NAME}:sdcore_config",
        relation2=f"{NMS_CHARM_NAME}:sdcore_config",
    )
    await ops_test.model.integrate(
        relation1=f"{APPLICATION_NAME}:logging",
        relation2=f"{GRAFANA_AGENT_APP_NAME}:logging-provider",
    )
    await ops_test.model.integrate(
        relation1=f"{APPLICATION_NAME}:metrics-endpoint",
        relation2=f"{GRAFANA_AGENT_APP_NAME}:metrics-endpoint",
    )
    await ops_test.model.wait_for_idle(
        apps=[APPLICATION_NAME],
        status="active",
        timeout=TIMEOUT,
    )


@pytest.mark.abort_on_fail
async def test_remove_nrf_and_wait_for_blocked_status(ops_test: OpsTest, deploy):
    assert ops_test.model
    await ops_test.model.remove_application(NRF_APP_NAME, block_until_done=True)
    await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="blocked", timeout=60)


@pytest.mark.abort_on_fail
async def test_restore_nrf_and_wait_for_active_status(ops_test: OpsTest, deploy):
    assert ops_test.model
    await _deploy_nrf(ops_test)
    await ops_test.model.integrate(relation1=APPLICATION_NAME, relation2=NRF_APP_NAME)
    await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="active", timeout=TIMEOUT)


@pytest.mark.abort_on_fail
async def test_remove_tls_and_wait_for_blocked_status(ops_test: OpsTest, deploy):
    assert ops_test.model
    await ops_test.model.remove_application(TLS_PROVIDER_APP_NAME, block_until_done=True)
    await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="blocked", timeout=60)


@pytest.mark.abort_on_fail
async def test_restore_tls_and_wait_for_active_status(ops_test: OpsTest, deploy):
    assert ops_test.model
    await _deploy_tls_provider(ops_test)
    await ops_test.model.integrate(relation1=APPLICATION_NAME, relation2=TLS_PROVIDER_APP_NAME)
    await ops_test.model.integrate(relation1=NMS_CHARM_NAME, relation2=TLS_PROVIDER_APP_NAME)
    await ops_test.model.integrate(relation1=NRF_APP_NAME, relation2=TLS_PROVIDER_APP_NAME)
    await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="active", timeout=TIMEOUT)


@pytest.mark.abort_on_fail
async def test_remove_nms_and_wait_for_blocked_status(ops_test: OpsTest, deploy):
    assert ops_test.model
    await ops_test.model.remove_application(NMS_CHARM_NAME, block_until_done=True)
    await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="blocked", timeout=60)


@pytest.mark.abort_on_fail
async def test_restore_nms_and_wait_for_active_status(ops_test: OpsTest, deploy):
    assert ops_test.model
    await _deploy_nms(ops_test)
    await ops_test.model.integrate(
        relation1=f"{APPLICATION_NAME}:sdcore_config",
        relation2=f"{NMS_CHARM_NAME}:sdcore_config",
    )
    await ops_test.model.wait_for_idle(apps=[APPLICATION_NAME], status="active", timeout=TIMEOUT)


@pytest.mark.abort_on_fail
async def test_when_scale_app_beyond_1_then_only_one_unit_is_active(ops_test: OpsTest, deploy):
    assert ops_test.model
    assert isinstance(app := ops_test.model.applications[APPLICATION_NAME], Application)
    await app.scale(3)
    await ops_test.model.wait_for_idle(
        apps=[APPLICATION_NAME], timeout=TIMEOUT, wait_for_at_least_units=3
    )
    unit_statuses = Counter(unit.workload_status for unit in app.units)
    assert unit_statuses.get("active") == 1
    assert unit_statuses.get("blocked") == 2


async def test_remove_app(ops_test: OpsTest, deploy):
    assert ops_test.model
    await ops_test.model.remove_application(APPLICATION_NAME, block_until_done=True)
