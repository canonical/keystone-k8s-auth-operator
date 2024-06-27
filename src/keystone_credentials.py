# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Implementation of keystone-credentials interface."""

import logging
from typing import Optional, Union

import ops
import pydantic
from backports.cached_property import cached_property

log = logging.getLogger(__name__)


class Data(pydantic.BaseModel, extra=pydantic.Extra.allow):
    """Databag from the relation."""

    credentials_host: pydantic.StrictStr
    credentials_protocol: pydantic.StrictStr
    credentials_port: int
    api_version: int


class KeystoneCredentialsRequires(ops.Object):
    """Requires side of keystone-credentials relation."""

    def __init__(self, charm: ops.CharmBase, endpoint="keystone"):
        super().__init__(charm, f"relation-{endpoint}")
        self.endpoint = endpoint
        events = charm.on[endpoint]
        self.relation_info = {}
        self.framework.observe(events.relation_joined, self._joined)

    def request_credentials(
        self,
        username,
        project=None,
        region=None,
        requested_roles=None,
        requested_grants=None,
        domain=None,
    ):
        """
        Request credentials from Keystone

        :side effect: set requested parameters on the keystone-credentials
                      relation

        Required parameter
        :param username: Username to be created.

        Optional parameters
        :param project: Project (tenant) name to be created. Defaults to
                        services project.
        :param requested_roles: Comma delimited list of roles to be created
        :param requested_grants: Comma delimited list of roles to be granted.
                                 Defaults to Admin role.
        :param domain: Keystone v3 domain the user will be created in. Defaults
                       to the Default domain.
        """
        self.relation_info = {
            "username": username,
            "project": project or "",
            "requested_roles": requested_roles or "",
            "requested_grants": requested_grants or "",
            "domain": domain or "",
        }
        if self.relation:
            self._joined(self)

    def _joined(self, event: Union[ops.EventBase, "KeystoneCredentialsRequires"]):
        event.relation.data[self.model.unit].update(**self.relation_info)

    @cached_property
    def relation(self) -> Optional[ops.Relation]:
        """The relation to the credentials, or None."""
        return self.model.get_relation(self.endpoint)

    @cached_property
    def _raw_data(self) -> Optional[ops.RelationData]:
        if self.relation and self.relation.units:
            first = list(self.relation.units)[0]
            return self.relation.data[first]
        return None

    @cached_property
    def _data(self) -> Optional[Data]:
        raw = self._raw_data
        return Data(**raw) if raw else None

    def evaluate_relation(self, event) -> Optional[str]:
        """Determine if relation is ready."""
        no_relation = not self.relation or (
            isinstance(event, ops.RelationBrokenEvent) and event.relation is self.relation
        )
        if not self.is_ready:
            if no_relation:
                return f"Missing required {self.endpoint}"
            return f"Waiting for {self.endpoint}"
        return None

    @property
    def is_ready(self):
        """Whether the request for this instance has been completed."""
        try:
            self._data
        except pydantic.ValidationError as ve:
            log.error(f"{self.endpoint} relation data not yet valid. ({ve}")
            return False
        if self._data is None:
            log.error(f"{self.endpoint} relation data not yet available.")
            return False
        return True

    @property
    def credentials_protocol(self):
        if not self.is_ready:
            return None
        return self._data.credentials_protocol

    @property
    def credentials_host(self):
        if not self.is_ready:
            return None
        return self._data.credentials_host

    @property
    def credentials_port(self):
        if not self.is_ready:
            return None
        return self._data.credentials_port

    @property
    def api_version(self):
        if not self.is_ready:
            return None
        return self._data.api_version
