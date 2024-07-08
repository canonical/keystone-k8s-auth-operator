import unittest.mock as mock
from pathlib import Path

import pytest

from provider_manifests import ProviderManifests


@pytest.fixture
def provider_manifest():
    mock_charm = mock.MagicMock()
    mock_config = mock.MagicMock()
    mock_kube_control = mock.MagicMock()
    mock_certificates = mock.MagicMock()
    mock_credentials = mock.MagicMock()

    mock_config.available_data = {
        "keystone-policy-configmap": "[]",
    }

    provider = ProviderManifests(
        mock_charm, mock_config, mock_kube_control, mock_certificates, mock_credentials
    )
    mock_credentials.credentials_protocol = "https"
    mock_credentials.credentials_host = "keystone.example.com"
    mock_credentials.credentials_port = 5000
    mock_credentials.api_version = 3

    cert_map = mock.MagicMock()
    cert_map.cert = "test-crt"
    cert_map.key = "test-key"
    mock_certificates.ca = Path("tests/data/ca.crt").read_text()
    mock_certificates.server_certs_map = {"k8s-keystone-auth.kube-system": cert_map}

    yield provider


def test_provider_manifest_evaluate_ok(provider_manifest):
    assert provider_manifest.config == {
        "image-registry": provider_manifest.kube_control.get_registry_location(),
        "keystone-url": "https://keystone.example.com:5000/v3",
        "keystone-ssl-ca": provider_manifest.certificates.ca,
        "keystone-policy-configmap": "[]",
        "release": None,
        "tls.crt": "test-crt",
        "tls.key": "test-key",
    }

    assert provider_manifest.evaluate() is None


def test_provider_manifest_invalid_certificate(provider_manifest):
    provider_manifest.charm_config.available_data["keystone-ssl-ca"] = "junk"
    assert (
        provider_manifest.evaluate()
        == "Certificate 'keystone-ssl-ca' is not valid PEM certificate."
    )
