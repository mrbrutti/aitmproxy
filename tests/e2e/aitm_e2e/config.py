"""Per-run `aitm` config generation.

Builds the minimal YAML a real `aitm` core needs for an e2e scenario, with
DEDICATED (free) ports so a run never collides with the operator's running app
(default proxy 8080 / browser 8081 / web 8082). The config shape is the one
proven by apps/web/scripts/live-env.mjs, verified against crates/aitm-core/src/config.rs.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _yaml_str(v: str) -> str:
    return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'


@dataclass
class CoreConfig:
    """The inputs to one `aitm` config.yaml. Ports default to None -> caller fills
    them with free_port() before writing."""

    proxy_port: int
    bus_port: int = 0  # 0 = ephemeral; read the real port from --bus-endpoint-file
    browser_proxy_port: int = 0
    agent_token: str = "e2e-agent-token"
    operator_token: str = "e2e-operator-secret"
    scope_entries: list[str] = field(default_factory=list)
    allow_agent_widen: bool = True
    poc_dir: str | None = None
    poc_out_dir: str | None = None
    findings_dir: str | None = None
    l4_enabled: bool = False
    l4_flags: dict[str, bool] = field(default_factory=dict)
    # CA: a per-run dir isolates the MITM CA from the operator's real store; aitm
    # writes <ca_dir>/ca.crt on boot (use aitm_e2e.tls.ca_cert to locate it).
    ca_dir: str | None = None
    # ssl_insecure: trust a self-signed UPSTREAM cert (for TLS echo origins).
    ssl_insecure: bool = False
    # Rhai scripting: scripts_dir is auto-loaded + is where script.save writes;
    # allow_agent_authoring opens script.save/reload to an agent frontend.
    rhai_scripts_dir: str | None = None
    rhai_allow_agent_authoring: bool = False

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
        if self.l4_enabled:
            lines.append("l4:")
            lines.append("  enabled: true")
            for flag, val in self.l4_flags.items():
                lines.append(f"  {flag}: {str(bool(val)).lower()}")
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


def write_config(path: str, cfg: CoreConfig) -> str:
    """Write the config YAML to `path` (0600) and return the path."""
    with open(path, "w", encoding="utf-8") as f:
        f.write(cfg.to_yaml())
    os.chmod(path, 0o600)
    return path
