from datetime import datetime, timezone
from typing import Any, NewType

import hvac
import requests
from attrs import define, field, fields, frozen
from cryptography import x509
from hvac.api.secrets_engines import Pki
from kmg.kitchen.attrs import simple_validator
from kmg.kitchen.datetime import must_be_tz_aware
from kmg.kitchen.requests import checked

from cert.certs.utils import End, Ttl


@frozen
class EngineMountConfig:
    path: str

    default_lease_ttl: Ttl
    max_lease_ttl: Ttl

    description: str | None = None

    def mount(self, client: hvac.Client) -> requests.Response:
        "NOT idempotent"
        r: requests.Response = client.sys.enable_secrets_engine(
            "pki",
            self.path,
            self.description,
            config=dict(
                default_lease_ttl=self.default_lease_ttl,
                max_lease_ttl=self.max_lease_ttl,
            ),
        )
        r.raise_for_status()
        return r


@define
class GenerateRootRequest:
    issuer_name: str
    cn: str
    end: End
    permitted_dns_domains: list[str] = field(factory=list)

    def __call__(self, pki: Pki, path: str) -> dict[str, Any] | requests.Response:
        extra = dict(issuer_name=self.issuer_name)
        extra[self.end._VAULT_FIELD_NAME] = str(self.end)

        return pki.generate_root(
            mount_point=path, type="internal", common_name=self.cn, extra_params=extra
        )


@define
class Allow:
    domains: list[str]
    bare: bool | None = field(kw_only=True, default=None)
    subdomains: bool | None = field(kw_only=True, default=None)
    glob: bool | None = field(kw_only=True, default=None)

    ip_sans: bool | None = field(kw_only=True, default=None)

    def todict(self) -> dict[str, Any]:
        return {
            f"allow_{attr.name}": getattr(self, attr.name)
            for attr in fields(type(self))
        }


@define
class CreateRoleReq:
    name: str
    issuer_ref: str
    end: End
    max_ttl: str

    allow: Allow

    allow_wildcard_certificates: bool | None = field(
        kw_only=True, default=None
    )  # TODO does this belong in `allow`?

    enforce_hostnames: bool = True

    # TODO: server / client use? does that override the CSR?

    def __call__(self, pki: Pki, path: str):
        extra = {
            attr.name: getattr(self, attr.name)
            for attr in fields(type(self))
            if attr.name not in {"allow", "name"}
        } | self.allow.todict()
        extra[self.end._VAULT_FIELD_NAME] = str(self.end)

        return pki.create_or_update_role(
            name=self.name, mount_point=path, extra_params={}
        )


@define
class RootGenerationSteps:
    """
    this is a separate class just to keep them grouped together.
    still need to figure out how to check the workflow, y'know?
    """

    path: str
    pki: Pki

    def gen_root(self, req: GenerateRootRequest):
        return req(self.pki, self.path)

    def make_role(self):
        ...

    def config_urls(self):
        ...


@define
class GenIntermediateRequest:
    cn: str
    alt_names: list[str] = field(default=[])

    # TODO: why would add_basic_constraints default to False?

    def __call__(self, pki: Pki, path: str):
        return pki.generate_intermediate(
            type="internal",
            common_name=self.cn,
            extra_params=dict(alt_names=self.alt_names),
            mount_point=path,
        )


@define
class IntermediateGenerationSteps:
    ...


@define
class FullWorkflowSteps:
    def make_root_engine(self):
        ...

    def do_root(self):
        ...

    def make_intermed_engine(self):
        ...

    def do_intermed(self):
        ...
