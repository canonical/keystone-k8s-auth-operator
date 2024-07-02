#!/usr/bin/env python3
# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.
"""Deploy and manage Keystone K8s Auth."""

import base64
import logging
import os
import shutil
from pathlib import Path
from urllib.parse import urlparse

import charms.contextual_status as status
import ops
from charms.reconciler import Reconciler
from ops.interface_kube_control import KubeControlRequirer
from ops.interface_tls_certificates import CertificatesRequires
from ops.manifests import Collector, ManifestClientError

from config import CharmConfig
from keystone_credentials import KeystoneCredentialsRequires
from provider_manifests import COMMON_NAME, ProviderManifests

log = logging.getLogger(__name__)


class KeystoneK8sCharm(ops.CharmBase):
    """Deploy and manage the keystone-auth for K8s."""

    stored = ops.StoredState()

    def __init__(self, *args):
        super().__init__(*args)

        # Ensure kubeconfig environment
        self._kubeconfig_path.parent.mkdir(parents=True, exist_ok=True)

        # Relation Validator and datastore
        self.kube_control = KubeControlRequirer(self)
        self.certificates = CertificatesRequires(self)
        self.credentials = KeystoneCredentialsRequires(self)
        # Config Validator and datastore
        self.charm_config = CharmConfig(self)

        self.stored.set_default(config_hash=0)  # hashed value of the provider config once valid
        self.stored.set_default(destroying=False)  # True when the charm is being shutdown

        self.provider = ProviderManifests(
            self, self.charm_config, self.kube_control, self.certificates, self.credentials
        )
        self.collector = Collector(self.provider)

        self.reconciler = Reconciler(self, self.reconcile)
        self.framework.observe(self.on.list_versions_action, self._list_versions)
        self.framework.observe(self.on.list_resources_action, self._list_resources)
        self.framework.observe(self.on.scrub_resources_action, self._scrub_resources)
        self.framework.observe(self.on.sync_resources_action, self._sync_resources)
        self.framework.observe(self.on.generate_webhook_config_action, self._generate_webhook)
        self.framework.observe(self.on.get_service_url_action, self._get_service_url)
        self.framework.observe(self.on.update_status, self._on_update_status)

    @property
    def _ca_cert_path(self) -> Path:
        return Path(f"/srv/{self.unit.name}/ca.crt")

    @property
    def _kubeconfig_path(self) -> Path:
        path = f"/srv/{self.unit.name}/kubeconfig"
        os.environ["KUBECONFIG"] = path
        return Path(path)

    def _list_versions(self, event):
        self.collector.list_versions(event)

    def _list_resources(self, event):
        resources = event.params.get("resources", "")
        return self.collector.list_resources(event, "", resources)

    def _scrub_resources(self, event):
        resources = event.params.get("resources", "")
        return self.collector.scrub_resources(event, "", resources)

    def _sync_resources(self, event):
        resources = event.params.get("resources", "")
        try:
            self.collector.apply_missing_resources(event, "", resources)
        except ManifestClientError:
            msg = "Failed to apply missing resources. API Server unavailable."
            event.set_results({"result": msg})

    def _generate_webhook(self, event: ops.ActionEvent):
        if not (ca := self.certificates.ca):
            event.fail("CA certificate not available")
        elif not (url := self.provider.get_service_url(fqdn=event.params.get("fqdn"))):
            event.fail("Service URL not available")
        else:
            file_content = Path("templates/keystone-apiserver-webhook.yaml").read_text()
            ca_encoded = base64.b64encode(ca.encode()).decode()
            formatted = file_content.format(certificate_authority_data=ca_encoded, service_url=url)
            event.set_results({"webhook-config": formatted})

    def _get_service_url(self, event: ops.ActionEvent):
        if url := self.provider.get_service_url(fqdn=event.params.get("fqdn")):
            event.set_results({"service-url": url})
        else:
            event.fail("Service URL not available")

    def _update_status(self):
        unready = self.collector.unready
        if unready:
            status.add(ops.WaitingStatus(", ".join(unready)))
            raise status.ReconcilerError("Waiting for deployment")
        elif not self.provider.get_service_url():
            status.add(ops.WaitingStatus("Waiting for service"))
            raise status.ReconcilerError("Service is not ready")
        else:
            self.unit.set_workload_version(self.collector.short_version)
            if self.unit.is_leader():
                self.app.status = ops.ActiveStatus(self.collector.long_version)

    def _on_update_status(self, _: ops.EventBase) -> None:
        if not self.reconciler.stored.reconciled:
            return
        try:
            with status.context(self.unit):
                self._update_status()
        except status.ReconcilerError:
            log.exception("Can't update_status")

    def _check_credentials(self, event):
        self.unit.status = ops.MaintenanceStatus("Evaluating Keystone credentials relation.")
        self.credentials.request_credentials(self.app.name)
        if evaluation := self.credentials.evaluate_relation(event):
            status_type = ops.WaitingStatus if "Waiting" in evaluation else ops.BlockedStatus
            status.add(status_type(evaluation))
            raise status.ReconcilerError(evaluation)

    def _request_certificates(self):
        sans = []
        if url := self.provider.get_service_url(fqdn=True):
            sans.append(urlparse(url).hostname)
        if url := self.provider.get_service_url():
            sans.append(urlparse(url).hostname)
        self.certificates.request_server_cert(cn=COMMON_NAME, sans=sans)

    def _check_certificates(self, event):
        self.unit.status = ops.MaintenanceStatus("Evaluating certificates.")
        if evaluation := self.certificates.evaluate_relation(event):
            status_type = ops.WaitingStatus if "Waiting" in evaluation else ops.BlockedStatus
            status.add(status_type(evaluation))
            raise status.ReconcilerError(evaluation)
        self._request_certificates()
        self._ca_cert_path.write_text(self.certificates.ca)

    def _check_kube_control(self, event):
        self.unit.status = ops.MaintenanceStatus("Evaluating kubernetes authentication.")
        if evaluation := self.kube_control.evaluate_relation(event):
            status_type = ops.WaitingStatus if "Waiting" in evaluation else ops.BlockedStatus
            status.add(status_type(evaluation))
            raise status.ReconcilerError(evaluation)
        self.kube_control.set_auth_request(self.unit.name)
        if not self.kube_control.get_auth_credentials(self.unit.name):
            status.add(ops.WaitingStatus("Waiting for kube-control: unit credentials"))
            raise status.ReconcilerError("Waiting for kube-control: unit credentials")
        self.kube_control.create_kubeconfig(
            self._ca_cert_path, self._kubeconfig_path, "root", self.unit.name
        )

    def _check_config(self):
        self.unit.status = ops.MaintenanceStatus("Evaluating charm config.")
        if evaluation := self.charm_config.evaluate():
            status.add(ops.BlockedStatus(evaluation))
            raise status.ReconcilerError(evaluation)

    def reconcile(self, event: ops.EventBase) -> None:
        """Reconcile the charm state."""
        if self._destroying(event):
            leader = self.unit.is_leader()
            log.info("purge manifests if leader(%s) event(%s)", leader, event)
            if leader:
                self._cleanup()
            return

        self._check_credentials(event)
        self._check_certificates(event)
        self._check_kube_control(event)
        self._check_config()
        hash = self.evaluate_manifests()
        self.install_manifests(config_hash=hash)
        self._update_status()

    def evaluate_manifests(self) -> int:
        """Evaluate all manifests."""
        self.unit.status = ops.MaintenanceStatus("Evaluating Keystone K8s Auth manifests.")
        new_hash = 0
        for manifest in self.collector.manifests.values():
            if evaluation := manifest.evaluate():
                status.add(ops.BlockedStatus(evaluation))
                raise status.ReconcilerError(evaluation)
            new_hash += manifest.hash()
        return new_hash

    def install_manifests(self, config_hash: int) -> None:
        if int(self.stored.config_hash) == config_hash:
            log.info(f"No config changes detected. config_hash={config_hash}")
            return
        if self.unit.is_leader():
            self.unit.status = ops.MaintenanceStatus("Deploying Keystone K8s Auth")
            self.unit.set_workload_version("")
            for manifest in self.collector.manifests.values():
                try:
                    manifest.apply_manifests()
                except ManifestClientError as e:
                    failure_msg = " -> ".join(map(str, e.args))
                    status.add(ops.WaitingStatus(failure_msg))
                    log.warning("Encountered retriable installation error: %s", e)
                    raise status.ReconcilerError(failure_msg)

        self.stored.config_hash = config_hash

    @status.on_error(ops.WaitingStatus("Manifest purge failed."))
    def _cleanup(self):
        if self.stored.config_hash:
            self.unit.status = ops.MaintenanceStatus("Cleaning up K8s Keystone Auth")
            for manifest in self.collector.manifests.values():
                manifest.delete_manifests(ignore_unauthorized=True)
        self.unit.status = ops.MaintenanceStatus("Shutting down")
        shutil.rmtree(self._kubeconfig_path.parent, ignore_errors=True)

    def _destroying(self, event: ops.EventBase) -> bool:
        """Check if the charm is being destroyed."""
        if self.stored.destroying:
            return True
        if isinstance(event, (ops.StopEvent, ops.RemoveEvent)):
            self.stored.destroying = True
            return True
        elif isinstance(event, ops.RelationBrokenEvent) and event.relation.name in [
            "keystone",
            "kube-control",
            "certificates",
        ]:
            return True
        return False


if __name__ == "__main__":
    ops.main.main(KeystoneK8sCharm)
