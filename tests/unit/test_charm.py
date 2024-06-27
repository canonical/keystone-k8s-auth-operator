# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing

import unittest.mock as mock
from pathlib import Path

import pytest
import yaml
from ops.model import ActiveStatus, BlockedStatus, WaitingStatus
from ops.testing import Harness

from charm import KeystoneK8sCharm


@pytest.fixture
def harness():
    harness = Harness(KeystoneK8sCharm)
    try:
        yield harness
    finally:
        harness.cleanup()


@pytest.fixture(autouse=True)
def mock_kubeconfig(tmpdir):
    kubeconfig = Path(tmpdir) / "kubeconfig"
    with mock.patch.object(
        KeystoneK8sCharm,
        "_kubeconfig_path",
        new_callable=mock.PropertyMock(return_value=kubeconfig),
    ):
        yield kubeconfig


@pytest.fixture(autouse=True)
def mock_ca_cert(tmpdir):
    ca_cert = Path(tmpdir) / "ca.crt"
    with mock.patch.object(
        KeystoneK8sCharm, "_ca_cert_path", new_callable=mock.PropertyMock(return_value=ca_cert)
    ):
        yield ca_cert


@pytest.fixture()
def credentials():
    with mock.patch("charm.KeystoneCredentialsRequires") as mocked:
        credentials = mocked.return_value
        credentials.evaluate_relation.return_value = None
        credentials.cloud_conf_b64 = b"abc"
        credentials.endpoint_tls_ca = b"def"
        yield credentials


@pytest.fixture()
def certificates():
    with mock.patch("charm.CertificatesRequires") as mocked:
        certificates = mocked.return_value
        certificates.ca = "abcd"
        certificates.evaluate_relation.return_value = None
        yield certificates


@pytest.fixture()
def kube_control():
    with mock.patch("charm.KubeControlRequirer") as mocked:
        kube_control = mocked.return_value
        kube_control.evaluate_relation.return_value = None
        kube_control.get_registry_location.return_value = "rocks.canonical.com/cdk"
        kube_control.get_controller_taints.return_value = []
        kube_control.get_controller_labels.return_value = []
        kube_control.relation.app.name = "kubernetes-control-plane"
        kube_control.relation.units = [f"kubernetes-control-plane/{_}" for _ in range(2)]
        yield kube_control


def test_waits_for_credentials(harness):
    harness.begin_with_initial_hooks()
    charm = harness.charm
    assert isinstance(charm.unit.status, BlockedStatus)
    assert charm.unit.status.message == "Missing required keystone"

    # Test adding the integrator relation
    rel_cls = type(charm.credentials)
    rel_cls.relation = property(rel_cls.relation.func)
    rel_cls._data = property(rel_cls._data.func)
    rel_cls._raw_data = property(rel_cls._raw_data.func)
    rel_id = harness.add_relation("keystone", "keystone")
    assert isinstance(charm.unit.status, WaitingStatus)
    assert charm.unit.status.message == "Waiting for keystone"
    harness.add_relation_unit(rel_id, "keystone/0")
    assert isinstance(charm.unit.status, WaitingStatus)
    assert charm.unit.status.message == "Waiting for keystone"
    harness.update_relation_data(
        rel_id,
        "keystone/0",
        yaml.safe_load(Path("tests/data/keystone_data.yaml").read_text()),
    )
    assert isinstance(charm.unit.status, BlockedStatus)
    assert charm.unit.status.message == "Missing required certificates"


@pytest.mark.usefixtures("credentials")
def test_waits_for_certificates(harness):
    harness.begin_with_initial_hooks()
    charm = harness.charm
    assert isinstance(charm.unit.status, BlockedStatus)
    assert charm.unit.status.message == "Missing required certificates"

    # Test adding the certificates relation
    rel_cls = type(charm.certificates)
    rel_cls.relation = property(rel_cls.relation.func)
    rel_cls._data = property(rel_cls._data.func)
    rel_cls._raw_data = property(rel_cls._raw_data.func)
    rel_id = harness.add_relation("certificates", "easyrsa")
    assert isinstance(charm.unit.status, WaitingStatus)
    assert charm.unit.status.message == "Waiting for certificates"
    harness.add_relation_unit(rel_id, "easyrsa/0")
    assert isinstance(charm.unit.status, WaitingStatus)
    assert charm.unit.status.message == "Waiting for certificates"
    harness.update_relation_data(
        rel_id,
        "easyrsa/0",
        yaml.safe_load(Path("tests/data/certificates_data.yaml").read_text()),
    )
    assert isinstance(charm.unit.status, BlockedStatus)
    assert charm.unit.status.message == "Missing required kube-control relation"


@mock.patch("ops.interface_kube_control.KubeControlRequirer.create_kubeconfig")
@pytest.mark.usefixtures("credentials", "certificates")
def test_waits_for_kube_control(mock_create_kubeconfig, harness, caplog):
    harness.begin_with_initial_hooks()
    charm = harness.charm
    assert isinstance(charm.unit.status, BlockedStatus)
    assert charm.unit.status.message == "Missing required kube-control relation"

    # Add the kube-control relation
    rel_cls = type(charm.kube_control)
    rel_cls.relation = property(rel_cls.relation.func)
    rel_cls._data = property(rel_cls._data.func)
    rel_id = harness.add_relation("kube-control", "kubernetes-control-plane")
    assert isinstance(charm.unit.status, WaitingStatus)
    assert charm.unit.status.message == "Waiting for kube-control relation"

    harness.add_relation_unit(rel_id, "kubernetes-control-plane/0")
    assert isinstance(charm.unit.status, WaitingStatus)
    assert charm.unit.status.message == "Waiting for kube-control relation"
    mock_create_kubeconfig.assert_not_called()

    caplog.clear()
    harness.update_relation_data(
        rel_id,
        "kubernetes-control-plane/0",
        yaml.safe_load(Path("tests/data/kube_control_data.yaml").read_text()),
    )
    mock_create_kubeconfig.assert_called_once_with(
        charm._ca_cert_path, charm._kubeconfig_path, "root", charm.unit.name
    )
    assert charm.unit.status == ActiveStatus("Ready")
    storage_messages = {r.message for r in caplog.records if "provider" in r.filename}

    assert storage_messages == {
        "Encode secret data for k8s-keystone-auth.",
        "Patching server_url for Deployment/k8s-keystone-auth",
        "Setting secret for Deployment/k8s-keystone-auth",
    }

    caplog.clear()
