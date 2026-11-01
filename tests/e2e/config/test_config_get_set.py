#!/usr/bin/env python3
# e2e: tier=T1 surface=config
"""config.get round-trips the configuration the core REALLY runs with -- and nothing secret.

Everything is asserted on ground truth, never a fixture or a frozen default:

  WRITE   a config file with a deliberately NON-default value for every field that
          `config.get` reports (listen, ssl_insecure, max_flows, max_flow_bytes,
          scope.entries incl. a wildcard, scope.allow_agent_widen, limits.*, ca.dir,
          the mcp loopback port, browser.engine, the poc dirs) boots a real core;
  READ    `config.get` over the bus returns exactly those values, leaf by leaf;
  REAL    each reported value is cross-checked against something the command does
          not control: the proxy is really serving on the reported `listen`
          (proxy.status, and a real request through that port that an independent
          upstream RECORDED), the bus this very connection uses is the reported
          `mcp.port` (the rendezvous endpoint file), `ca.dir` is where ca.export
          really finds the certificate on disk, the poc dirs exist, scope.list agrees;
  REDACT  the agent token and the operator token (random per run, known to us) appear
          nowhere in the view and no key is named like a secret;
  ROLES   agent and operator get the identical view (config.get is a Read command);
  CLI     a fresh one-shot `aitm --config <same file> config get` renders the identical
          view (cross-surface agreement, bus vs CLI);
  SET     there is no `config.set` on the bus: the config FILE is the setter. The one
          runtime mutator that touches a reported field is scope.add/remove (operator):
          it changes the LIVE scope (scope.list; a request.send that was refused
          out-of-scope now reaches the upstream, which RECORDS it) while config.get keeps
          reporting the CONFIGURED entries -- it is a view of the configuration the core
          was started with (the attached Config, crates/aitm-plugins/src/control.rs), not
          of the guard's live scope set. Should a `config.set` ever appear on the bus this
          test FAILS loudly so the round trip is extended instead of silently uncovered.

Two ways to get a core:
  * default: boot our own (`Aitm.server`) on dedicated free ports with the config we
    wrote -- the strongest form, every expected value is ours;
  * attach: when the runner exports AITM_BUS_ADDR + AITM_BUS_TOKEN (optionally
    AITM_BUS_OPERATOR_TOKEN, AITM_PROXY_ADDR, AITM_E2E_WORKDIR holding its JSON aitm.yaml)
    that core is used; the WRITE side is then the runner's config file, so the leaf
    comparison covers the keys that file sets and the live cross-checks run unchanged.
Nothing global is left changed: the one scope entry added is ours and removed again.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, free_port, ok, repo_root, section  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.proxyutil import via_proxy  # noqa: E402
from aitm_e2e.upstream import Upstream  # noqa: E402

TOOL = "config.get"
SETTER = "config.set"
OUT_OF_SCOPE = "out of scope"  # GuardError::OutOfScope renders "host X is out of scope"
# Every top-level field `redacted()` emits (crates/aitm-plugins/src/control.rs).
REPORTED = ("listen", "ssl_insecure", "max_flows", "max_flow_bytes", "scope", "limits",
            "ca", "mcp", "browser", "poc_dir", "poc_out_dir")


# ----------------------------------------------------------------------------
# the WRITE side


@dataclass
class ConfigUnderTest(CoreConfig):
    """CoreConfig plus every knob `config.get` reports, each set to a NON-default
    value so an echoed default can never pass for a round trip. Written as JSON
    (valid YAML; the loader is serde_yaml) so nothing here depends on the harness's
    YAML emitter."""

    ssl_insecure: bool = True  # default false
    max_flows: int = 321  # default DEFAULT_MAX_FLOWS
    max_flow_bytes: int = 4 * 1024 * 1024  # default DEFAULT_MAX_FLOW_BYTES
    limits: dict = field(default_factory=lambda: {  # defaults 150/50/25/10/10MiB
        "global_rps": 123,
        "per_host_rps": 45,
        "max_concurrency": 7,
        "host_error_budget": 3,
        "max_body_bytes": 2 * 1024 * 1024,
    })
    ca_dir: str = ""  # a private 0700 dir: the user's real CA is never touched
    engine: str = "obscura"

    def document(self) -> dict:
        doc = {
            "listen": f"127.0.0.1:{self.proxy_port}",
            "ssl_insecure": self.ssl_insecure,
            "max_flows": self.max_flows,
            "max_flow_bytes": self.max_flow_bytes,
            "scope": {"entries": list(self.scope_entries), "allow_agent_widen": self.allow_agent_widen},
            "limits": dict(self.limits),
            # audit_log is a sibling of dir, never inside it (CaConfig docs).
            "ca": {"dir": self.ca_dir, "audit_log": os.path.join(os.path.dirname(self.ca_dir), "ca-audit.jsonl")},
            "mcp": {
                "operator_token": self.operator_token,
                "transport": {"loopback_tcp": {"port": self.bus_port, "token": self.agent_token}},
            },
            "browser": {"engine": self.engine, "proxy_addr": f"127.0.0.1:{self.browser_proxy_port}"},
            "poc": {"dir": self.poc_dir, "out_dir": self.poc_out_dir},
        }
        if self.findings_dir:
            doc["findings"] = {"dir": self.findings_dir}
        return doc

    def to_yaml(self) -> str:  # what Aitm.server() writes to disk
        return json.dumps(self.document(), indent=2) + "\n"


class AttachedCore:
    """A core the runner already started (env contract). Quacks like `Aitm` for
    BusClient.operator()/agent(): `bus_addr` and `cfg.agent_token/operator_token`."""

    def __init__(self) -> None:
        host, port = os.environ["AITM_BUS_ADDR"].rsplit(":", 1)
        self.bus_addr = (host.strip("[]"), int(port))
        self.cfg = SimpleNamespace(
            agent_token=os.environ["AITM_BUS_TOKEN"],
            operator_token=os.environ.get("AITM_BUS_OPERATOR_TOKEN") or None,
        )
        proxy = os.environ.get("AITM_PROXY_ADDR")
        self.proxy_port = int(proxy.rsplit(":", 1)[1]) if proxy else None
        self.config_path = None
        self.document = None
        work = os.environ.get("AITM_E2E_WORKDIR")
        for name in ("aitm.yaml", "config.yaml"):
            path = os.path.join(work, name) if work else None
            if path and os.path.isfile(path):
                try:
                    with open(path, encoding="utf-8") as fh:
                        self.document = json.load(fh)  # the e2e boot writes JSON-as-YAML
                    self.config_path = path
                except ValueError:
                    pass  # real YAML: no file-side expectation, the live cross-checks still run
                break

    def stop(self) -> None:
        pass  # not ours to stop


def expected_view(doc: dict) -> dict:
    """The `config.get` view a config FILE (dict form) must produce, for the keys the
    file sets. Mirrors `redacted()` in crates/aitm-plugins/src/control.rs."""
    exp: dict = {k: doc[k] for k in ("listen", "ssl_insecure", "max_flows", "max_flow_bytes") if k in doc}
    scope = doc.get("scope") or {}
    sub = {k: scope[k] for k in ("entries", "allow_agent_widen") if k in scope}
    if sub:
        exp["scope"] = sub
    limits = doc.get("limits") or {}
    sub = {k: limits[k] for k in ("global_rps", "per_host_rps", "max_concurrency", "host_error_budget", "max_body_bytes") if k in limits}
    if sub:
        exp["limits"] = sub
    ca = doc.get("ca") or {}
    sub = {k: ca[k] for k in ("dir", "allow_agent_install") if k in ca}
    if sub:
        exp["ca"] = sub
    loopback = ((doc.get("mcp") or {}).get("transport") or {}).get("loopback_tcp")
    if isinstance(loopback, dict):
        exp["mcp"] = {"transport": "loopback_tcp"}
        if "port" in loopback:
            exp["mcp"]["port"] = loopback["port"]
    browser = doc.get("browser") or {}
    if "engine" in browser:
        exp["browser"] = {"engine": browser["engine"]}
    poc = doc.get("poc") or {}
    if "dir" in poc:
        exp["poc_dir"] = poc["dir"]
    if "out_dir" in poc:
        exp["poc_out_dir"] = poc["out_dir"]
    return exp


def compare(expected: dict, got, path: str = "") -> tuple[int, list[str]]:
    """Leaf by leaf: prints an ok line per matching leaf, returns (leaves, mismatches)."""
    leaves, mism = 0, []
    for key, want in expected.items():
        here = f"{path}{key}"
        if not isinstance(got, dict) or key not in got:
            leaves += 1
            mism.append(f"{here}: missing (wanted {want!r})")
            continue
        have = got[key]
        if isinstance(want, dict):
            n, m = compare(want, have, here + ".")
            leaves += n
            mism += m
        else:
            leaves += 1
            if have == want:
                ok(f"{here} == {want!r}")
            else:
                mism.append(f"{here}: got {have!r}, wanted {want!r}")
    return leaves, mism


def all_keys(value, prefix: str = ""):
    if isinstance(value, dict):
        for k, v in value.items():
            yield prefix + k
            yield from all_keys(v, prefix + k + ".")
    elif isinstance(value, list):
        for v in value:
            yield from all_keys(v, prefix)


def active(bus: BusClient, tool: str, params: dict, tries: int = 5):
    """An active action as the agent: ('ok', value) | ('error', message). The
    127.0.0.1 rate bucket may be shared with parallel tests; a transient throttle is
    retried, never mistaken for a scope verdict."""
    status, val = "error", ""
    for _ in range(tries):
        status, val = bus.try_call(tool, params)
        if status == "ok" or "rate limited" not in str(val):
            return status, val
        time.sleep(0.3)
    return status, val


def aitm_binary() -> str:
    return os.environ.get("AITM_BIN") or os.path.join(repo_root(), "target", "debug", "aitm")


# ----------------------------------------------------------------------------


def main() -> int:
    attach = bool(os.environ.get("AITM_BUS_ADDR") and os.environ.get("AITM_BUS_TOKEN"))
    up = Upstream().start()  # the independent observer; NOT in the configured scope
    core = None
    agent = op = None
    ca_tmp = None
    added_scope = None
    try:
        if attach:
            section("attach: the runner's core (AITM_BUS_ADDR); its config file is the WRITE side")
            core = AttachedCore()
            doc = core.document
            proxy_port = core.proxy_port
            ok(f"bus {core.bus_addr[0]}:{core.bus_addr[1]}, proxy port {proxy_port}, "
               f"config file {'read: ' + core.config_path if doc else 'not available (AITM_E2E_WORKDIR)'}")
        else:
            section("write: a NON-default value for every reported field; boot a real core on that file")
            ca_tmp = tempfile.mkdtemp(prefix="aitm-e2e-config-")  # 0700
            cfg = ConfigUnderTest(
                proxy_port=free_port(),
                bus_port=free_port(),  # explicit, so the configured port and the bound port can be compared
                browser_proxy_port=free_port(),
                agent_token=secrets.token_hex(16),
                operator_token=secrets.token_hex(16),
                scope_entries=["e2e-config.invalid", "*.e2e-config.example"],  # never contacted
                allow_agent_widen=False,  # the secure default; the harness default is True
                ca_dir=os.path.join(ca_tmp, "ca"),
            )
            core = Aitm.server(cfg)
            doc = cfg.document()  # poc dirs were filled in by Aitm._prep before the write
            proxy_port = cfg.proxy_port
            ok(f"core up: proxy 127.0.0.1:{cfg.proxy_port}, bus {core.bus_addr[0]}:{core.bus_addr[1]}, upstream {up.base}")
            check(core.bus_addr[1] == cfg.bus_port,
                  f"the bus bound the CONFIGURED port {cfg.bus_port} (endpoint file says {core.bus_addr[1]})")

        section("read: config.get over the bus as the AGENT (it is a Read command)")
        agent = BusClient.agent(core)
        if core.cfg.operator_token:
            op = BusClient.operator(core)  # used for the Sensitive cross-checks (ca.export, scope.add)
        names = set(agent.tool_names())
        check(TOOL in names, f"{TOOL} is registered on the live bus ({len(names)} tools)")
        view = agent.call(TOOL, {})
        check(isinstance(view, dict) and bool(view), f"{TOOL} returned a non-empty object")
        missing = [k for k in REPORTED if k not in view]
        check(not missing, f"every field redacted() reports is present ({len(REPORTED)} keys; missing: {missing})")
        for key in ("scope", "limits", "ca", "mcp", "browser"):
            check(isinstance(view.get(key), dict), f"{key} is an object")

        section("round trip: every value the config FILE set comes back exactly")
        if doc is None:
            ok("attach mode without a readable JSON config file: file-side leg not available; live cross-checks follow")
        else:
            expected = expected_view(doc)
            leaves, mism = compare(expected, view)
            check(not mism, f"{leaves} configured values echoed exactly (mismatches: {mism})")
            if not attach:
                uncovered = sorted(set(REPORTED) - set(expected))
                check(not uncovered, f"every reported field was set NON-default by the file, so no echoed default "
                                     f"passed for a round trip ({leaves} leaves; uncovered: {uncovered})")

        section("ground truth: each reported value matches what the core REALLY does")
        status = agent.call("proxy.status", {})
        check(status.get("listening") is True, f"proxy.status: the proxy is really listening ({status})")
        check(status.get("address") == view["listen"], f"proxy.status.address == config.get.listen ({view['listen']})")
        listen_port = int(str(view["listen"]).rsplit(":", 1)[1])
        if proxy_port is not None:
            check(listen_port == proxy_port, f"reported listen port {listen_port} is the dedicated proxy port {proxy_port}")
        marker = f"/config-get-{secrets.token_hex(6)}"
        resp = via_proxy(listen_port, "GET", f"{up.base}{marker}")  # the REPORTED port, not a known one
        check(resp.status == 200, f"a real request through the REPORTED listen port got {resp.status} from the upstream")
        hits = [r for r in up.received if r["path"] == marker]
        check(len(hits) == 1, f"the independent upstream RECORDED exactly that request ({len(hits)} hit): listen is the live proxy")

        check(view["mcp"].get("transport") == "loopback_tcp", f"mcp.transport is loopback_tcp (this connection's kind): {view['mcp']}")
        if view["mcp"].get("port"):
            check(view["mcp"]["port"] == core.bus_addr[1],
                  f"mcp.port {view['mcp']['port']} is the port THIS connection is on ({core.bus_addr[1]})")
        else:
            ok("mcp.port is 0 in the file (ephemeral): config.get echoes the CONFIGURED 0; the bound port is only in the endpoint file")
        check("token" not in view["mcp"], "mcp carries no token field")

        # ca.export is Sensitive (refused to the agent under the default `auto` policy),
        # so the operator runs it; without an operator token fall back to the disk.
        ca_dir = view["ca"]["dir"]
        if op is not None:
            ca = op.confirm("ca.export", {})
            check(isinstance(ca, dict) and os.path.realpath(ca.get("dir", "")) == os.path.realpath(ca_dir),
                  f"ca.export (operator) works out of the reported ca.dir ({ca_dir})")
            cert = ca.get("path", "") if isinstance(ca, dict) else ""
            check(os.path.isfile(cert) and os.path.realpath(cert).startswith(os.path.realpath(ca_dir) + os.sep),
                  f"the CA certificate really exists on disk under the reported ca.dir ({cert})")
        else:
            check(os.path.isdir(ca_dir), f"no operator token: at least the reported ca.dir exists on disk ({ca_dir})")
        if not attach:
            check(os.path.realpath(ca_dir).startswith(os.path.realpath(ca_tmp) + os.sep),
                  "ca.dir is the private 0700 dir this test created (the user's real CA was never touched)")

        for key in ("poc_dir", "poc_out_dir"):
            if view.get(key):
                check(os.path.isdir(view[key]), f"reported {key} exists on disk: {view[key]}")

        live = agent.call("scope.list", {})
        configured = view["scope"]["entries"]
        if attach:
            check(set(configured) <= set(live), f"every configured scope entry is in the live scope (configured {configured}, live {live})")
        else:
            check(live == configured, f"fresh core: live scope.list == the configured entries, in order ({live})")
            check("*.e2e-config.example" in configured, "the wildcard entry survived the file -> core -> bus trip verbatim")
        check(up.authority not in configured, f"the upstream {up.authority} is NOT in the configured scope (needed below)")

        section("redaction: no token and no secret-shaped key anywhere in the view")
        text = json.dumps(view)
        check(core.cfg.agent_token not in text, "the AGENT token appears nowhere in the view")
        if core.cfg.operator_token:
            check(core.cfg.operator_token not in text, "the OPERATOR token appears nowhere in the view")
        suspicious = [k for k in all_keys(view)
                      if any(s in k.lower() for s in ("token", "secret", "password")) or k.lower().endswith("key")]
        check(not suspicious, f"no secret-shaped key in the view (found: {suspicious})")

        section("roles: the operator gets the identical redacted view")
        if op is not None:
            op_view = op.call(TOOL, {})
            check(op_view == view, "operator view == agent view (same configuration, same redaction)")
        else:
            ok("no operator token from the runner; operator legs not run")

        section("cross-surface: a fresh one-shot `aitm config get` on the same file renders the same view")
        cfg_path = core.config_path if attach else os.path.join(core.workdir, "config.yaml")
        binary = aitm_binary()
        if cfg_path and os.path.isfile(binary) and (not attach or os.environ.get("AITM_BIN")):
            env = {k: v for k, v in os.environ.items() if k != "AITM_CONFIG"}
            env["RUST_LOG"] = "warn"
            run = subprocess.run([binary, "--config", cfg_path, "config", "get"], stdin=subprocess.DEVNULL,
                                 capture_output=True, text=True, timeout=60, env=env)
            check(run.returncode == 0, f"one-shot exited {run.returncode} (stderr tail: {run.stderr.strip()[-300:]!r})")
            try:
                cli_view = json.loads(run.stdout)
            except ValueError:
                fail(f"one-shot stdout is not JSON: {run.stdout[:300]!r}")
            check(cli_view == view, "CLI view == bus view (the two surfaces agree on the configuration)")
        else:
            ok("one-shot leg not run: " + ("no config path" if not cfg_path else
               f"binary {binary} missing" if not os.path.isfile(binary) else
               "attach mode without AITM_BIN naming the runner's binary"))

        section("set: the FILE is the setter; scope.add changes the LIVE scope, config.get keeps the CONFIGURED view")
        if op is None:
            ok("runtime scope leg needs an operator connection (scope.add); not run")
        else:
            tag = secrets.token_hex(4)
            before = f"/active-before-{tag}"
            st, msg = active(agent, "request.send", {"authority": up.authority, "path": before})
            check(st == "error" and OUT_OF_SCOPE in str(msg),
                  f"agent request.send to the unscoped upstream is refused out of scope ({str(msg)[:100]})")
            time.sleep(0.3)
            check(not [r for r in up.received if r["path"] == before], "...and the upstream recorded nothing (refused means not sent)")

            op.confirm("scope.add", {"host": up.authority})
            added_scope = up.authority
            live_after_add = op.call("scope.list", {})
            check(up.authority in live_after_add, f"scope.add (operator) put {up.authority} in the LIVE scope: {live_after_add}")

            after = f"/active-after-{tag}"
            st, fid = active(agent, "request.send", {"authority": up.authority, "path": after})
            check(st == "ok" and isinstance(fid, str) and bool(fid), f"the same request.send now runs (flow {fid!r})")
            got = [r for r in up.received if r["path"] == after]
            check(len(got) == 1, f"the upstream RECORDED exactly that request ({len(got)}): the live scope change is real")

            view_after = agent.call(TOOL, {})
            check(view_after["scope"]["entries"] == configured and up.authority not in view_after["scope"]["entries"],
                  "config.get still reports the CONFIGURED entries: the configuration view, not the live guard scope")
            check(view_after == view, "...and nothing else in the view moved")

            removed = op.call("scope.remove", {"host": up.authority})
            added_scope = None
            check(removed is True and up.authority not in op.call("scope.list", {}), "scope.remove restored the live scope")
            check(agent.call(TOOL, {}) == view, "config.get is unchanged across the whole add/remove cycle")

        # A coverage tripwire for THIS test's own name, not a frozen claim about the
        # core: the day a setter ships on the bus, this fails loudly and gets extended.
        check(SETTER not in names, f"{SETTER} is not on the bus (the file is the setter); if this fails, extend this test to round-trip it")

        ok("PASS: config.get echoes the configured values, each cross-checked live; secrets redacted; "
           "agent == operator == CLI; live scope moves, configured view does not")
    finally:
        if op is not None and added_scope:
            try:
                op.try_call("scope.remove", {"host": added_scope})
            except Exception:  # noqa: BLE001 -- cleanup must not mask the verdict
                pass
        for bus in (op, agent):
            if bus is not None:
                bus.close()
        if core is not None:
            core.stop()
        up.stop()
        if ca_tmp:
            shutil.rmtree(ca_tmp, ignore_errors=True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # noqa: BLE001 -- surface boot/bus failures as a FAIL with context
        fail(f"{type(e).__name__}: {e}")
