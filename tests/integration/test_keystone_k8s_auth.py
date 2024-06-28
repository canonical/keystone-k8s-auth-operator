# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.
import json
import logging
import shlex
from pathlib import Path

import pytest
from juju.application import Application
from juju.unit import Unit
from lightkube.resources.apps_v1 import Deployment
from lightkube.resources.core_v1 import Service

log = logging.getLogger(__name__)


@pytest.mark.abort_on_fail
async def test_build_and_deploy(ops_test):
    charm = next(Path(".").glob("keystone-k8s-auth*.charm"), None)
    if not charm:
        log.info("Build Charm...")
        charm = await ops_test.build_charm(".")

    overlays = [
        ops_test.Bundle("kubernetes-core", channel="edge"),
        Path("tests/data/charm.yaml"),
    ]

    bundle, *overlays = await ops_test.async_render_bundles(*overlays, charm=charm.resolve())

    log.info("Deploy Charm...")
    model = ops_test.model_full_name
    cmd = f"juju deploy -m {model} {bundle} " + " ".join(f"--overlay={f}" for f in overlays)
    rc, stdout, stderr = await ops_test.run(*shlex.split(cmd))
    assert rc == 0, f"Bundle deploy failed: {(stderr or stdout).strip()}"

    log.info(stdout)
    await ops_test.model.block_until(
        lambda: "keystone-k8s-auth" in ops_test.model.applications, timeout=60
    )

    await ops_test.model.wait_for_idle(wait_for_active=True, timeout=60 * 60)


async def test_deployment_running(kubernetes):
    objects = []
    async for svc in kubernetes.list(Service, namespace="kube-system"):
        objects.append(svc)
    assert any(s.metadata.name == "k8s-keystone-auth-service" for s in objects)

    async for dep in kubernetes.list(Deployment, namespace="kube-system"):
        objects.append(dep)
    assert any(d.metadata.name == "k8s-keystone-auth" for d in objects)
    deployment = next(d for d in objects if d.metadata.name == "k8s-keystone-auth")
    assert deployment.status.readyReplicas == deployment.spec.replicas


@pytest.fixture(scope="module")
async def generate_webhook(ops_test):
    keystone_k8s_auth = ops_test.model.applications["keystone-k8s-auth"]
    result = await keystone_k8s_auth.units[0].run_action("generate-webhook-config")
    await result.wait()
    assert result.status == "completed"
    return result.results["webhook-config"]


@pytest.fixture(scope="module")
async def service_url(ops_test):
    keystone_k8s_auth = ops_test.model.applications["keystone-k8s-auth"]
    result = await keystone_k8s_auth.units[0].run_action("get-service-url")
    await result.wait()
    assert result.status == "completed"
    return result.results["service-url"]


async def test_actions(generate_webhook, service_url):
    assert generate_webhook is not None
    assert service_url is not None


@pytest.fixture(scope="module")
async def integrate_with_control_plane(ops_test, generate_webhook, service_url):
    control_plane = ops_test.model.applications["kubernetes-control-plane"]
    await control_plane.set_config(
        {
            "authorization-webhook-config-file": generate_webhook,
            "authorization-mode": "Node,Webhook,RBAC",
            "authn-webhook-endpoint": service_url,
        }
    )
    async with ops_test.fast_forward():
        await ops_test.model.wait_for_idle(wait_for_active=True, timeout=5 * 60)


@pytest.fixture(scope="module")
async def keystone_client(ops_test, tmp_path_factory):
    tmp_path = tmp_path_factory.mktemp("keystone-client")
    keystone: Application = ops_test.model.applications["keystone"]
    keystone_client: Application = ops_test.model.applications["keystone-client"]
    control_plane: Application = ops_test.model.applications["kubernetes-control-plane"]
    keystone_unit: Unit = keystone.units[0]
    keystone_client_unit: Unit = keystone_client.units[0]
    control_plane_unit: Unit = control_plane.units[0]

    control_plane_config = await control_plane.get_config()
    channel = control_plane_config["channel"]["value"]
    # install kubectl and client-keystone-auth snaps into keystone-client
    await keystone_client_unit.run(
        f"""
        snap install kubectl --classic --channel={channel};
        snap install client-keystone-auth --classic --channel={channel};
        mkdir -p /home/ubuntu/.kube;
        chown ubuntu:ubuntu /home/ubuntu/.kube;
        """,
        block=True,
    )
    # copy ca.cert into keystone-client
    await control_plane_unit.run(
        "cp /root/cdk/ca.crt /home/ubuntu/ca.crt; chmod 644 /home/ubuntu/ca.crt", block=True
    )
    await control_plane_unit.scp_from("/home/ubuntu/ca.crt", tmp_path / "ca.crt")
    await keystone_client_unit.scp_to(
        tmp_path / "ca.crt",
        "/home/ubuntu/ca.crt",
    )
    # copy kubeconfig into keystone-client
    context = {
        "keystone_user": "admin",
        "keystone_password": "testpw",
        "keystone_project": "admin",
        "keystone_domain": "admin_domain",
        "keystone_server_url": f"https://{keystone_unit.public_address}:5000/v3",
        "kubernetes_api_server": f"https://{control_plane_unit.public_address}:6443",
    }
    kubeconfig_template = Path("tests/data/keystone-kubeconfig.yaml").read_text()
    kubeconfig: Path = tmp_path / "kubeconfig"
    kubeconfig.write_text(kubeconfig_template.format(**context))
    await keystone_client_unit.scp_to(kubeconfig, "/home/ubuntu/.kube/config")
    yield keystone_client_unit


@pytest.mark.usefixtures("integrate_with_control_plane")
async def test_client_auth(ops_test, keystone_client: Unit):
    keystone_k8s_auth = ops_test.model.applications["keystone-k8s-auth"]
    policies = [
        {
            "users": {"projects": ["admin"], "user": ["admin"]},
            "resource_permissions": {"default/pods": ["get", "list", "watch"]},
        }
    ]
    await keystone_k8s_auth.set_config({"keystone-policy-configmap": json.dumps(policies)})

    # verify auth fail - bad user
    kubectl = "kubectl --kubeconfig=/home/ubuntu/.kube/config"
    cmd = f"{kubectl} --context bad-user-context get clusterroles"
    output = await keystone_client.run(f'su - ubuntu -c "{cmd}"', block=True)
    assert output.status == "completed"
    stderr = output.results["stderr"]
    assert "invalid user credentials" in stderr.lower(), stderr

    # verify auth fail - bad password
    cmd = f"{kubectl} --context bad-password-context get clusterroles"
    output = await keystone_client.run(f'su - ubuntu -c "{cmd}"', block=True)
    assert output.status == "completed"
    stderr = output.results["stderr"]
    assert "invalid user credentials" in stderr.lower(), stderr

    # verify auth failure on pods outside of default namespace
    cmd = f"{kubectl} --context good-context get pod -n kube-system"
    output = await keystone_client.run(f'su - ubuntu -c "{cmd}"', block=True)
    assert output.status == "completed"
    stderr = output.results["stderr"]
    assert 'cannot list resource "pods"' in stderr.lower(), stderr

    # verify auth success on pods
    cmd = f"{kubectl} --context good-context get pod"
    output = await keystone_client.run(f'su - ubuntu -c "{cmd}"', block=True)
    code, stderr = output.results["return-code"], output.results["stderr"]
    assert code == 0, stderr


async def test_remove_charm(ops_test, kubernetes):
    keystone_k8s_auth: Application = ops_test.model.applications["keystone-k8s-auth"]
    await keystone_k8s_auth.remove()
    await ops_test.model.block_until(
        lambda: "keystone-k8s-auth" not in ops_test.model.applications, timeout=10 * 60
    )
    objects = []
    async for svc in kubernetes.list(Service, namespace="kube-system"):
        objects.append(svc)
    assert not any(s.metadata.name == "k8s-keystone-auth-service" for s in objects)

    async for dep in kubernetes.list(Deployment, namespace="kube-system"):
        objects.append(dep)
    assert not any(d.metadata.name == "k8s-keystone-auth" for d in objects)
