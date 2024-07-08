# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.
"""Config Management for the keystone-k8s-auth charm."""

import base64
import logging
from typing import Optional

log = logging.getLogger(__name__)


class CharmConfig:
    """Representation of the charm configuration."""

    def __init__(self, charm):
        """Creates a CharmConfig object from the configuration data."""
        self.config = charm.config

    @property
    def available_data(self):
        """Parse valid charm config into a dict, drop keys if unset or invalid."""
        data = dict(**self.config)
        for key, value in dict(**self.config).items():
            if value == "" or value is None:
                del data[key]

        if cert := data.get("keystone-ssl-ca"):
            try:
                data["keystone-ssl-ca"] = base64.b64decode(cert.strip().encode()).decode()
            except Exception:
                log.info("keystone-ssl-ca is not base64 encoded, continuing as this can be okay")

        return data

    def evaluate(self) -> Optional[str]:
        """Determine if configuration is valid."""
        return None
