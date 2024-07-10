# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.
"""Implementation of keystone-k8s-auth specific details of the kubernetes manifests."""

import base64
import datetime
import logging
import pickle
import shlex
import ssl
from hashlib import md5
from typing import Dict, List, Optional

from lightkube.codecs import AnyResource
from lightkube.models.apps_v1 import Deployment
from lightkube.models.core_v1 import EnvVar
from lightkube.resources.core_v1 import ConfigMap, Secret, Service
from ops.interface_tls_certificates import CertificatesRequires
from ops.manifests import (
    Addition,
    ConfigRegistry,
    HashableResource,
    ManifestLabel,
    Manifests,
    Patch,
)

log = logging.getLogger(__file__)
COMMON_NAME = "k8s-keystone-auth.kube-system"
NAMESPACE = "kube-system"
RESOURCE_NAME = "k8s-keystone-auth"
SERVICE_NAME = "k8s-keystone-auth-service"
SECRET_NAME = "keystone-auth-certs"


class CreateSecret(Addition):
    """Create secret for the deployment.

    a secret named k8s-keystone-auth in the kube-system namespace
    """

    REQUIRED_CONFIG = {"tls.crt", "tls.key"}

    def __call__(self) -> Optional[AnyResource]:
        """Craft the secrets object for the deployment."""

        tls_cert: str = self.manifests.config.get("tls.crt", "")
        tls_key: str = self.manifests.config.get("tls.key", "")
        ca_cert: str = self.manifests.config.get("keystone-ssl-ca")
        log.info("Encode secret data for k8s-keystone-auth.")
        struct = dict(
            metadata={"name": SECRET_NAME, "namespace": NAMESPACE},
            type="kubernetes.io/tls",
            data={
                "tls.crt": base64.b64encode(tls_cert.encode()).decode(),
                "tls.key": base64.b64encode(tls_key.encode()).decode(),
            },
        )
        if ca_cert:
            log.info("Adding ca.crt to secret.")
            struct["data"]["ca.crt"] = base64.b64encode(ca_cert.encode()).decode()
        return Secret.from_dict(struct)


class UpdateDeployment(Patch):
    """Update the Deployment."""

    REQUIRED_CONFIG = {"keystone-url"}

    def __call__(self, obj):
        """Patch the k8s-keyston-auth deployment."""
        if not (obj.kind == "Deployment" and obj.metadata.name == RESOURCE_NAME):
            return
        obj: Deployment = obj

        for volume in obj.spec.template.spec.volumes:
            if volume.secret:
                volume.secret.secretName = SECRET_NAME
                log.info(f"Setting secret for {obj.kind}/{obj.metadata.name}")

        server_url: str = self.manifests.config.get("keystone-url", "")
        ca_cert: str = self.manifests.config.get("keystone-ssl-ca")
        replicas: int = self.manifests.config.get("replicas", 2)
        extra_args: List[str] = shlex.split(self.manifests.config.get("extra-args", ""))

        log.info("Patching server_url for %s/%s", obj.kind, obj.metadata.name)
        obj.spec.replicas = replicas
        obj.spec.template.metadata.annotations = {}
        for container in obj.spec.template.spec.containers:
            if container.name == RESOURCE_NAME:
                container.args = container.args[:1] + extra_args
                for env in container.env:
                    if env.name == "OS_AUTH_URL":
                        env.value = server_url
                if ca_cert and server_url.startswith("https"):
                    container.env += [EnvVar(name="KEYSTONE_CA_FILE", value="/etc/pki/ca.crt")]


class Policy(Addition):
    REQUIRED_CONFIG = {"keystone-policy-configmap"}
    POLICY_NAME = "k8s-auth-policy"

    def __call__(self) -> Optional[AnyResource]:
        """Craft the policy config-map object."""
        policy: str = self.manifests.config.get("keystone-policy-configmap", "[]")

        return ConfigMap.from_dict(
            dict(
                metadata={"name": self.POLICY_NAME, "namespace": NAMESPACE},
                data={"policies": policy},
            )
        )


class ProviderManifests(Manifests):
    """Deployment Specific details for the k8s-keystone-auth."""

    def __init__(
        self, charm, charm_config, kube_control, certificates: CertificatesRequires, credentials
    ):
        super().__init__(
            RESOURCE_NAME,
            charm.model,
            "upstream/keystone_auth",
            [
                CreateSecret(self),
                ManifestLabel(self),
                ConfigRegistry(self),
                UpdateDeployment(self),
                Policy(self),
            ],
        )
        self.charm_config = charm_config
        self.kube_control = kube_control
        self.certificates = certificates
        self.credentials = credentials

    @property
    def config(self) -> Dict:
        """Returns current config available from charm config and joined relations."""
        config: Dict = {}

        if self.certificates.is_ready and (
            cert := self.certificates.server_certs_map.get(COMMON_NAME)
        ):
            config["tls.crt"] = str(cert.cert)
            config["tls.key"] = str(cert.key)
            config["keystone-ssl-ca"] = self.certificates.ca

        if self.kube_control.is_ready:
            config["image-registry"] = self.kube_control.get_registry_location()

        if self.credentials.is_ready:
            config["keystone-url"] = "{}://{}:{}/v{}".format(
                self.credentials.credentials_protocol,
                self.credentials.credentials_host,
                self.credentials.credentials_port,
                self.credentials.api_version,
            )

        config.update(**self.charm_config.available_data)

        for key, value in dict(**config).items():
            if value == "" or value is None:
                del config[key]

        config["release"] = config.pop("release", None)
        return config

    def hash(self) -> int:
        """Calculate a hash of the current configuration."""
        return int(md5(pickle.dumps(self.config)).hexdigest(), 16)

    def evaluate(self) -> Optional[str]:
        """Determine if manifest_config can be applied to manifests."""
        release_path = self.manifest_path / self.current_release
        if not release_path.exists():
            return f"Release {self.current_release} does not exist."

        props = (
            CreateSecret.REQUIRED_CONFIG
            | UpdateDeployment.REQUIRED_CONFIG
            | Policy.REQUIRED_CONFIG
        )
        for prop in sorted(props):
            value = self.config.get(prop)
            if not value:
                return f"Manifests require the definition of '{prop}'"
        for certificate in ["keystone-ssl-ca"]:
            if err := self.validate_certificate(certificate):
                return err
        return None

    def validate_certificate(self, which_cert: str) -> Optional[str]:
        if self.config.get(which_cert) is None:
            return None
        try:
            cert: str = self.config.get(which_cert)
            ssl.PEM_cert_to_DER_cert(cert)
            return None
        except ValueError:
            msg = f"Certificate '{which_cert}' is not valid PEM certificate."
            log.error(msg)
            return msg

    def get_service_url(self, fqdn=False) -> Optional[str]:
        """Return the service url."""
        if fqdn:
            return f"https://{SERVICE_NAME}.{NAMESPACE}.svc.cluster.local:8443/webhook"
        try:
            svc: Service = self.client.get(Service, SERVICE_NAME, namespace=NAMESPACE)
            return f"https://{svc.spec.clusterIP}:8443/webhook"
        except Exception as e:
            log.error("Failed to get service url. ex=%s", e)
        return None

    def apply_manifests(self):
        """Apply the manifests to the cluster and restart deployments."""
        super().apply_manifests()
        for rsc in self.resources:
            self.restart(rsc)

    def restart(self, obj: HashableResource):
        """Restart the hashable object if its possible to do so."""
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        T = type(obj.resource)
        patch = obj.resource
        try:
            patch.spec.template.metadata.annotations["juju.io/restartedAt"] = timestamp
        except AttributeError:
            log.error("Cannot restart %s/%s", obj.kind, obj.name)
            return
        log.info("Restarting %s/%s", obj.kind, obj.name)
        self.client.patch(T, obj.name, patch, namespace=obj.namespace)
