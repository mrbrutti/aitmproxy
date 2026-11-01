"""Per-run `aitm` config generation.

Builds the minimal YAML a real `aitm` core needs for an e2e scenario, with
DEDICATED (free) ports so a run never collides with the operator's running app
(default proxy 8080 / browser 8081 / web 8082). The config shape is the one
proven by apps/web/scripts/live-env.mjs, verified against crates/aitm-core/src/config.rs.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from . import free_port


def _yaml_str(v: str) -> str:
    return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'


@dataclass
class ScannerSection:
    """The `scanner:` file section (scanner v2 spec D11). Only the keys that are
    set (not None / non-empty) are emitted, in D11 order, so a cell pins exactly
    the knobs it means to and the core's defaults cover the rest."""

    allow_agent_active: bool | None = None
    allow_agent_l4_fuzz: bool | None = None
    max_jobs: int | None = None
    history: int | None = None
    check_timeout_s: int | None = None
    default_profile: str | None = None
    ceilings: dict[str, int] = field(default_factory=dict)


def _l4_scope_entry(
    addr: str,
    prefix: int,
    lo: int,
    hi: int,
    interface: str,
    direction: str,
    capability: str,
    pps: int,
    burst: int,
) -> dict:
    # Exactly the keys of crates/aitm-proto-l4/src/types.rs::L4ScopeEntry (minus
    # the `#[serde(default)]` `id` and `source`); enum tokens are snake_case.
    return {
        "cidr": {"addr": addr, "prefix": prefix},
        "ports": {"lo": lo, "hi": hi},
        "interface": interface,
        "direction": direction,
        "capability": capability,
        "inject_rate": {"pps": pps, "burst": burst},
    }


def l4_inject_entry(
    addr: str = "127.0.0.1",
    prefix: int = 32,
    lo: int = 1,
    hi: int = 65535,
    interface: str = "*",
    direction: str = "outbound",
    pps: int = 200,
    burst: int = 400,
) -> dict:
    """An `l4.scope` entry granting `inject` (what the scanner's stream lane needs:
    `interface: "*"`, outbound, the target CIDR + ports)."""
    return _l4_scope_entry(addr, prefix, lo, hi, interface, direction, "inject", pps, burst)


def l4_capture_entry(
    addr: str = "127.0.0.0",
    prefix: int = 8,
    lo: int = 0,
    hi: int = 65535,
    interface: str = "*",
    direction: str = "inbound",
    pps: int = 200,
    burst: int = 400,
) -> dict:
    """An `l4.scope` entry granting `capture` (the packet lane's inbound permit;
    `inject_rate` is a required field of L4ScopeEntry so it is emitted here too)."""
    return _l4_scope_entry(addr, prefix, lo, hi, interface, direction, "capture", pps, burst)


@dataclass
class CoreConfig:
    """The inputs to one `aitm` config.yaml. The caller picks `proxy_port` (usually
    `free_port()`). `browser_proxy_port` 0 (the default) is resolved to a free port
    in `__post_init__`: before that fix the 0 was written verbatim as
    `proxy_addr: 127.0.0.1:0`, so a core started without an explicit port pointed
    obscura at port 0 and every browser navigation timed out (T2 live diagnosis,
    2026-11-01). Explicit `browser_proxy_port=free_port()` arguments stay valid."""

    proxy_port: int
    bus_port: int = 0  # 0 = ephemeral; read the real port from --bus-endpoint-file
    browser_proxy_port: int = 0  # 0 -> a free port, see __post_init__
    agent_token: str = "e2e-agent-token"
    operator_token: str = "e2e-operator-secret"
    scope_entries: list[str] = field(default_factory=list)
    allow_agent_widen: bool = True
    poc_dir: str | None = None
    poc_out_dir: str | None = None
    findings_dir: str | None = None
    l4_enabled: bool = False
    l4_flags: dict[str, bool] = field(default_factory=dict)
    # l4_scope_entries: `l4.scope` items (use l4_inject_entry / l4_capture_entry);
    # any entry forces `l4:` + `enabled: true`.
    l4_scope_entries: list[dict] = field(default_factory=list)
    # scanner: the `scanner:` file section (scanner v2 D11); None = omitted.
    scanner: ScannerSection | None = None
    # CA: a per-run dir isolates the MITM CA from the operator's real store; aitm
    # writes <ca_dir>/ca.crt on boot (use aitm_e2e.tls.ca_cert to locate it).
    ca_dir: str | None = None
    # ssl_insecure: trust a self-signed UPSTREAM cert (for TLS echo origins).
    ssl_insecure: bool = False
    # Rhai scripting: scripts_dir is auto-loaded + is where script.save writes;
    # allow_agent_authoring opens script.save/reload to an agent frontend.
    rhai_scripts_dir: str | None = None
    rhai_allow_agent_authoring: bool = False

    def __post_init__(self) -> None:
        # obscura dials the browser proxy by this literal address: 0 is never a
        # listenable port, so resolve it here rather than write it into the YAML.
        if self.browser_proxy_port == 0:
            self.browser_proxy_port = free_port()

    def to_yaml(self) -> str:
        lines: list[str] = [
            f"listen: 127.0.0.1:{self.proxy_port}",
            "browser:",
            f"  proxy_addr: 127.0.0.1:{self.browser_proxy_port}",
            "scope:",
            f"  allow_agent_widen: {str(self.allow_agent_widen).lower()}",
        ]
        if self.scope_entries:
            lines.append("  entries:")
            lines.extend(f"    - {_yaml_str(e)}" for e in self.scope_entries)
        if self.poc_dir or self.poc_out_dir or self.findings_dir:
            lines.append("poc:")
            if self.poc_dir:
                lines.append(f"  dir: {_yaml_str(self.poc_dir)}")
            if self.poc_out_dir:
                lines.append(f"  out_dir: {_yaml_str(self.poc_out_dir)}")
        if self.findings_dir:
            lines.append("findings:")
            lines.append(f"  dir: {_yaml_str(self.findings_dir)}")
        lines += [
            "mcp:",
            f"  operator_token: {_yaml_str(self.operator_token)}",
            "  transport:",
            "    loopback_tcp:",
            f"      port: {self.bus_port}",
            f"      token: {_yaml_str(self.agent_token)}",
        ]
        if self.scanner is not None:
            lines.extend(self._scanner_lines(self.scanner))
        if self.l4_enabled or self.l4_scope_entries:
            lines.append("l4:")
            lines.append("  enabled: true")
            for flag, val in self.l4_flags.items():
                lines.append(f"  {flag}: {str(bool(val)).lower()}")
            if self.l4_scope_entries:
                lines.append("  scope:")
                for entry in self.l4_scope_entries:
                    lines.extend(self._l4_scope_lines(entry))
        if self.ca_dir:
            lines.append("ca:")
            lines.append(f"  dir: {_yaml_str(self.ca_dir)}")
        if self.rhai_scripts_dir or self.rhai_allow_agent_authoring:
            lines.append("rhai:")
            if self.rhai_scripts_dir:
                lines.append(f"  scripts_dir: {_yaml_str(self.rhai_scripts_dir)}")
            if self.rhai_allow_agent_authoring:
                lines.append("  allow_agent_authoring: true")
        if self.ssl_insecure:
            lines.append("ssl_insecure: true")
        lines.append("")
        return "\n".join(lines)

    @staticmethod
    def _scanner_lines(sc: ScannerSection) -> list[str]:
        out = ["scanner:"]
        for key in ("allow_agent_active", "allow_agent_l4_fuzz"):
            val = getattr(sc, key)
            if val is not None:
                out.append(f"  {key}: {str(bool(val)).lower()}")
        for key in ("max_jobs", "history", "check_timeout_s"):
            val = getattr(sc, key)
            if val is not None:
                out.append(f"  {key}: {int(val)}")
        if sc.default_profile is not None:
            out.append(f"  default_profile: {sc.default_profile}")
        if sc.ceilings:
            out.append("  ceilings:")
            out.extend(f"    {k}: {int(v)}" for k, v in sc.ceilings.items())
        return out

    @staticmethod
    def _l4_scope_lines(entry: dict) -> list[str]:
        cidr = entry["cidr"]
        ports = entry["ports"]
        rate = entry["inject_rate"]
        return [
            "    - cidr:",
            f"        addr: {cidr['addr']}",
            f"        prefix: {int(cidr['prefix'])}",
            "      ports:",
            f"        lo: {int(ports['lo'])}",
            f"        hi: {int(ports['hi'])}",
            f"      interface: {_yaml_str(entry['interface'])}",
            f"      direction: {entry['direction']}",
            f"      capability: {entry['capability']}",
            "      inject_rate:",
            f"        pps: {int(rate['pps'])}",
            f"        burst: {int(rate['burst'])}",
        ]


def write_config(path: str, cfg: CoreConfig) -> str:
    """Write the config YAML to `path` (0600) and return the path."""
    with open(path, "w", encoding="utf-8") as f:
        f.write(cfg.to_yaml())
    os.chmod(path, 0o600)
    return path
