#!/usr/bin/env python3
# e2e: tier=T1 surface=start
"""AITM_* environment overrides WIN over the config file, exactly as documented.

The contract under test is `crates/aitm/src/env.rs` (applied in `crates/aitm/src/main.rs`
right after `config_file::load_settings`, on every path: server, `aitm web`, `aitm tui`,
one-shot CLI):

  AITM_CA_ALLOW_AGENT_INSTALL     -> ca.allow_agent_install
  AITM_SCOPE_ALLOW_AGENT_WIDEN    -> scope.allow_agent_widen
  AITM_L4_ALLOW_AGENT_WIDEN       -> l4.allow_agent_widen
  AITM_L4_ALLOW_AGENT_INJECT      -> l4.allow_agent_inject
  AITM_L4_ALLOW_AGENT_CAPTURE     -> l4.allow_agent_capture
  AITM_L4_ALLOW_AGENT_INTERCEPT   -> l4.allow_agent_intercept
  AITM_SCRIPTS                    -> extra Rhai scripts, `a.rhai:b.rhai`, APPENDED after the file's
  AITM_SCRIPTS_STRICT             -> rhai.strict (fail startup on a script that does not compile)

Truthiness rule (documented): `1`, `true`, `yes` case-insensitively => true; ANY other value
(including the empty string, `on`, `2`) => false; UNSET => the file's value stands.

Precedence can only be proven by controlling BOTH the file and the environment of the
process under test, so this test does, on dedicated free ports (never the operator's
8080/8081/8082) and in a scrubbed environment (every documented AITM_* var removed, then
only the cell's values set). Nothing is a fixture; every expectation is the file WE wrote
or the env WE set, and every observation is what the REAL binary did:

  MATRIX   the real binary, one fresh process per cell (`aitm --config F config get` and
           `aitm --config F l4 agent status`, the one-shot CLI shares main.rs's loader+env
           path with the server): 2 files (all gates closed / all gates open) x 12 raw
           values + unset. Every gate reports truthy(raw) when set, the file value when unset.
  STRICT   process GROUND TRUTH on AITM_SCRIPTS_STRICT: file strict:false + a broken script
           + env `1` => the process EXITS NON-ZERO naming strict; file strict:true + broken
           + env `0` => exits 0 and lists the good scripts (file's first, env's appended);
           control: file strict:true + env unset => exits non-zero (the file stands).
  CORE A   a live core whose FILE closes every gate and whose ENV opens them: config.get and
           l4.agent.status report open; with the agent policy at `all` (so the per-command
           CONFIG gate is the deciding dimension) the AGENT really widens scope (`scope.add`)
           and its `request.send` REACHES an independent echo-record upstream that RECORDS
           it; the agent really widens the L4 scope (`l4.scope.add` -> `l4.scope.list`).
  CORE B   the inverse: FILE opens every gate, ENV closes them (`0`, `false`, `no`, `off`,
           empty): reported closed; the agent's `scope.add` is REFUSED by the scope gate,
           its `request.send` is refused out-of-scope and the upstream RECORDED NOTHING;
           its `ca.install` is REFUSED by the ca gate (the refusal names the env bridge) and
           the refusal is in the CA audit log we own -- nothing touched the OS trust store;
           `l4.scope.add` is refused by the L4 widen gate and the L4 scope stays empty.
  CORE C   a live core whose FILE says `rhai.strict: true` with one declared script, whose
           ENV says AITM_SCRIPTS=<env.rhai>:<broken.rhai> and AITM_SCRIPTS_STRICT=0: it
           STARTS (the file's strict would have aborted on the broken script), script.list
           is [file script, env script] in that order with the broken one skipped (and
           named in the log), and a REAL request through the proxy arrives at the upstream
           carrying the header each script sets -- the env-named script is live in the
           chain, AFTER the file's (the shared header holds the env script's value).
  ATTACH   when the runner exports a core (AITM_BUS_ADDR + AITM_BUS_TOKEN), its config.get
           / l4.agent.status are cross-checked against the AITM_* vars in the inherited
           environment and the runner's config file (AITM_E2E_WORKDIR), so a runner that
           booted its core with an override gets that precedence verified live too.

Safety: Core B's `ca.install` is only attempted AFTER config.get reports the gate closed
(the gate reads the very same Config), and the file's `ca.dir`/`ca.audit_log` are private
temp paths -- the user's real CA and audit log are never read or written. Cores are stopped
by their own PID only; no global state is touched.
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
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aitm_e2e import check, fail, free_port, ok, repo_root, section, skip  # noqa: E402
from aitm_e2e.bus import BusClient  # noqa: E402
from aitm_e2e.config import CoreConfig  # noqa: E402
from aitm_e2e.core import Aitm  # noqa: E402
from aitm_e2e.proxyutil import via_proxy  # noqa: E402
from aitm_e2e.upstream import Upstream  # noqa: E402

# ---------------------------------------------------------------------------
# the documented contract (crates/aitm/src/env.rs)

CA_INSTALL = "AITM_CA_ALLOW_AGENT_INSTALL"
SCOPE_WIDEN = "AITM_SCOPE_ALLOW_AGENT_WIDEN"
L4_WIDEN = "AITM_L4_ALLOW_AGENT_WIDEN"
L4_INJECT = "AITM_L4_ALLOW_AGENT_INJECT"
L4_CAPTURE = "AITM_L4_ALLOW_AGENT_CAPTURE"
L4_INTERCEPT = "AITM_L4_ALLOW_AGENT_INTERCEPT"
SCRIPTS = "AITM_SCRIPTS"
SCRIPTS_STRICT = "AITM_SCRIPTS_STRICT"

BOOL_VARS = (CA_INSTALL, SCOPE_WIDEN, L4_WIDEN, L4_INJECT, L4_CAPTURE, L4_INTERCEPT)
ALL_VARS = BOOL_VARS + (SCRIPTS, SCRIPTS_STRICT, "AITM_CONFIG")

# l4.agent.status key <- env var
L4_GATES = {"widen": L4_WIDEN, "inject": L4_INJECT, "capture": L4_CAPTURE, "intercept": L4_INTERCEPT}

TRUTHY_RAW = ("1", "true", "yes", "TRUE", "Yes", "tRuE")
FALSY_RAW = ("0", "false", "no", "off", "on", "2", "")


def truthy(raw: str) -> bool:
    """The documented rule, restated independently of the Rust (`is_truthy`)."""
    return raw.lower() in ("1", "true", "yes")


# ---------------------------------------------------------------------------
# environment control


def clean_env(overrides: dict[str, str] | None = None, *, rust_log: str | None = None) -> dict[str, str]:
    """A copy of our environment with EVERY documented AITM_* override removed (the runner
    may have set some), then exactly `overrides` applied."""
    env = {k: v for k, v in os.environ.items() if k not in ALL_VARS}
    if rust_log is not None:
        env["RUST_LOG"] = rust_log
    env.update(overrides or {})
    return env


@contextmanager
def process_env(overrides: dict[str, str]):
    """Temporarily make os.environ a clean_env(overrides): `Aitm.server` spawns the child
    with `dict(os.environ)`, so this is how a live core gets its cell's environment."""
    saved = dict(os.environ)
    try:
        os.environ.clear()
        os.environ.update(clean_env(overrides))
        yield
    finally:
        os.environ.clear()
        os.environ.update(saved)


# ---------------------------------------------------------------------------
# the WRITE side: a config FILE with every gated knob set explicitly


@dataclass
class StartConfig(CoreConfig):
    """CoreConfig plus the knobs the env bridge overrides, each written EXPLICITLY to the
    file (so a default can never pass for a file value), plus private CA paths. Written as
    JSON (valid YAML; the loader is serde_yaml) -- the shape test_config_get_set proved."""

    ca_dir: str = ""
    ca_audit_log: str = ""
    ca_allow_agent_install: bool = False
    l4: dict | None = None  # None => l4 absent (disabled)
    rhai_strict: bool | None = None
    scripts: list[str] = field(default_factory=list)

    def document(self) -> dict:
        doc: dict = {
            "listen": f"127.0.0.1:{self.proxy_port}",
            "browser": {"proxy_addr": f"127.0.0.1:{self.browser_proxy_port}"},
            "scope": {"entries": list(self.scope_entries), "allow_agent_widen": self.allow_agent_widen},
            "ca": {"dir": self.ca_dir, "audit_log": self.ca_audit_log,
                   "allow_agent_install": self.ca_allow_agent_install},
            "mcp": {
                "operator_token": self.operator_token,
                "transport": {"loopback_tcp": {"port": self.bus_port, "token": self.agent_token}},
            },
        }
        if self.poc_dir or self.poc_out_dir:
            doc["poc"] = {k: v for k, v in (("dir", self.poc_dir), ("out_dir", self.poc_out_dir)) if v}
        if self.l4 is not None:
            doc["l4"] = dict(self.l4)
        if self.rhai_strict is not None:
            doc["rhai"] = {"strict": self.rhai_strict}
        if self.scripts:
            doc["scripts"] = [{"path": p} for p in self.scripts]
        return doc

    def to_yaml(self) -> str:  # what Aitm.server() / write_config() put on disk
        return json.dumps(self.document(), indent=2) + "\n"


def l4_block(open_: bool) -> dict:
    return {"enabled": True, "allow_agent_widen": open_, "allow_agent_inject": open_,
            "allow_agent_capture": open_, "allow_agent_intercept": open_}


def rhai_script(name: str, header: str, value: str, order_value: str) -> str:
    """A minimal API-1 script: sets its own header and the shared order header."""
    return (
        f'const NAME = "{name}";\n'
        'const API = "1";\n'
        "fn on_request(flow) {\n"
        f'    flow.request.headers.set("{header}", "{value}");\n'
        f'    flow.request.headers.set("X-Aitm-E2e-Order", "{order_value}");\n'
        "}\n"
    )


BROKEN_RHAI = (
    'const NAME = "e2e-broken";\nconst API = "1";\n'
    'fn on_request(flow) {\n    flow.request.headers.set("X-Aitm", "1";\n}\n'  # missing ','
)


# ---------------------------------------------------------------------------
# helpers


def aitm_binary() -> str:
    return os.environ.get("AITM_BIN") or os.path.join(repo_root(), "target", "debug", "aitm")


def oneshot(cfg_path: str, argv: list[str], env: dict[str, str]) -> tuple[int, str, str]:
    run = subprocess.run([aitm_binary(), "--config", cfg_path, *argv], env=env, stdin=subprocess.DEVNULL,
                         capture_output=True, text=True, timeout=120)
    return run.returncode, run.stdout, run.stderr


def parse_json_tail(out: str):
    """The one-shot CLI's rendered value is the JSON document that ENDS stdout; the
    tracing sink may put log lines (timestamp/ANSI-prefixed) on stdout before it."""
    lines = out.splitlines()
    for i, line in enumerate(lines):
        if line[:1] in "[{":
            return json.loads("\n".join(lines[i:]))
    raise ValueError("no JSON document on stdout")


def oneshot_json(cfg_path: str, argv: list[str], env: dict[str, str], label: str):
    code, out, err = oneshot(cfg_path, argv, env)
    if code != 0:
        fail(f"{label}: `aitm {' '.join(argv)}` exited {code} (stderr tail: {err.strip()[-300:]!r})")
    try:
        return parse_json_tail(out)
    except ValueError:
        fail(f"{label}: `aitm {' '.join(argv)}` printed non-JSON: {out[:200]!r}")


def gates_view(cfg_path: str, env: dict[str, str], label: str) -> dict[str, bool]:
    """Every env-bridged boolean the real binary reports, keyed by its env var."""
    view = oneshot_json(cfg_path, ["config", "get"], env, label)
    l4 = oneshot_json(cfg_path, ["l4", "agent", "status"], env, label)
    got = {CA_INSTALL: view["ca"]["allow_agent_install"], SCOPE_WIDEN: view["scope"]["allow_agent_widen"]}
    for key, var in L4_GATES.items():
        got[var] = l4[key]
    return got


def active(bus: BusClient, tool: str, params: dict, tries: int = 6):
    """An active agent action: ('ok', value) | ('error', message); a transient 127.0.0.1
    rate-bucket throttle (shared with parallel tests) is retried, never read as a verdict."""
    status, val = "error", ""
    for _ in range(tries):
        status, val = bus.try_call(tool, params)
        if status == "ok" or "rate limited" not in str(val):
            return status, val
        time.sleep(0.4)
    return status, val


def wait_until(pred, timeout: float = 5.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if pred():
            return True
        time.sleep(0.1)
    return pred()


def boot(cfg: StartConfig, env: dict[str, str], label: str) -> Aitm:
    with process_env(env):
        try:
            return Aitm.server(cfg)
        except (RuntimeError, FileNotFoundError) as e:
            fail(f"{label}: the core did not start under env {sorted(env)}: {str(e)[:600]}")


def set_policy_all(op: BusClient, agent: BusClient, label: str) -> None:
    """Put the agent policy at `all`, the one posture under which a Sensitive agent call is
    deferred to its OWN per-command config gate (crates/aitm-mcp/src/server.rs
    `defers_to_command_gate`) -- so the config gate, i.e. the env override, decides."""
    r = op.confirm("agent.set", {"policy": "all"})
    check(isinstance(r, dict) and r.get("policy") == "all", f"{label}: operator agent.set policy=all ({r})")
    st = agent.call("agent.status", {})
    check(st.get("policy") == "all", f"{label}: agent.status confirms policy `all` ({st.get('policy')})")


L4_ENTRY = {"cidr": "192.0.2.0/24", "interface": "lo0", "direction": "outbound",
            "capability": "capture", "ports": "80"}  # RFC 5737 TEST-NET-1: never routed


# ---------------------------------------------------------------------------
# the legs


def leg_matrix(work: Path, ca_dir: str, ca_audit: str) -> None:
    section("MATRIX: the real binary reports truthy(raw) for EVERY gate, file closed or open")
    files = {}
    for state, open_ in (("closed", False), ("open", True)):
        cfg = StartConfig(proxy_port=0, browser_proxy_port=0, allow_agent_widen=open_,
                          ca_dir=ca_dir, ca_audit_log=ca_audit, ca_allow_agent_install=open_,
                          l4=l4_block(open_))
        path = work / f"matrix-{state}.json"
        path.write_text(cfg.to_yaml(), encoding="utf-8")
        files[state] = (str(path), open_)

    for state, (path, open_) in files.items():
        got = gates_view(path, clean_env(rust_log="error"), f"{state}/unset")
        wrong = {v: g for v, g in got.items() if g != open_}
        check(not wrong, f"file {state}, env UNSET: all {len(got)} gates report the FILE value {open_} (wrong: {wrong})")

    cells = 0
    for state, (path, open_) in files.items():
        for raw in TRUTHY_RAW + FALSY_RAW:
            want = truthy(raw)
            env = clean_env({v: raw for v in BOOL_VARS}, rust_log="error")
            got = gates_view(path, env, f"{state}/{raw!r}")
            wrong = {v: g for v, g in got.items() if g != want}
            cells += 1
            check(not wrong, f"file {state}, env {raw!r}: all gates == {want} (env wins; wrong: {wrong})")
    ok(f"{cells} cells x {len(BOOL_VARS)} gates: the env value decided every one; the file decided none")


def leg_strict(work: Path, ca_dir: str, ca_audit: str) -> None:
    section("STRICT: AITM_SCRIPTS_STRICT decides whether a broken script KILLS the process")
    good_file = work / "strict-file.rhai"
    good_env = work / "strict-env.rhai"
    broken = work / "strict-broken.rhai"
    good_file.write_text(rhai_script("e2e-strict-file", "X-Aitm-E2e-File", "f", "file"), encoding="utf-8")
    good_env.write_text(rhai_script("e2e-strict-env", "X-Aitm-E2e-Env", "e", "env"), encoding="utf-8")
    broken.write_text(BROKEN_RHAI, encoding="utf-8")

    lax = work / "strict-false.json"
    lax.write_text(StartConfig(proxy_port=0, browser_proxy_port=0, ca_dir=ca_dir, ca_audit_log=ca_audit,
                               rhai_strict=False, scripts=[str(good_file)]).to_yaml(), encoding="utf-8")
    strict = work / "strict-true.json"
    strict.write_text(StartConfig(proxy_port=0, browser_proxy_port=0, ca_dir=ca_dir, ca_audit_log=ca_audit,
                                  rhai_strict=True, scripts=[str(good_file), str(broken)]).to_yaml(),
                      encoding="utf-8")

    # control: the file's strict:true stands when the env is silent -> the process dies.
    code, _, err = oneshot(str(strict), ["script", "list"], clean_env(rust_log="error"))
    check(code != 0 and "strict" in err, f"control: file strict:true + broken script, env unset -> exit {code}, names strict")

    # env `1` over file strict:false -> dies.
    code, out, err = oneshot(str(lax), ["script", "list"],
                             clean_env({SCRIPTS: str(broken), SCRIPTS_STRICT: "1"}, rust_log="error"))
    check(code != 0 and "strict" in err,
          f"file strict:false + AITM_SCRIPTS=<broken> + AITM_SCRIPTS_STRICT=1 -> exit {code}, names strict (env won)")
    # The anyhow error is on stderr; the tracing sink that names the script is `fmt()`'s
    # default writer, stdout (crates/aitm/src/main.rs `init_tracing`). Read both.
    check("strict-broken" in out + err, "...and the failure names the broken script the ENV added")

    # env `0` over file strict:true -> lives, skips the broken one, lists file's then env's.
    code, out, err = oneshot(str(strict), ["script", "list"],
                             clean_env({SCRIPTS: str(good_env), SCRIPTS_STRICT: "0"}, rust_log="error"))
    check(code == 0, f"file strict:true + broken + AITM_SCRIPTS_STRICT=0 -> exit {code} (env won; the file would have killed it)")
    names = [s["name"] for s in parse_json_tail(out)] if code == 0 else []
    check(names == ["e2e-strict-file", "e2e-strict-env"],
          f"script list == [file script, env script] in chain order, broken skipped ({names})")
    check("strict-broken" in out + err, "...and the skipped broken script is named in the log (skip-and-log, not silence)")


def leg_core_a(work: Path) -> None:
    section("CORE A: FILE closes every gate, ENV opens them -> the AGENT really acts")
    up = Upstream().start()
    core = agent = op = None
    l4_id = None
    try:
        cfg = StartConfig(
            proxy_port=free_port(), agent_token=secrets.token_hex(16), operator_token=secrets.token_hex(16),
            allow_agent_widen=False, ca_allow_agent_install=False, l4=l4_block(False),
            ca_dir=str(work / "a-ca"), ca_audit_log=str(work / "a-ca-audit.jsonl"),
        )
        env = {SCOPE_WIDEN: "1", CA_INSTALL: "yes", L4_WIDEN: "true", L4_INJECT: "1", L4_CAPTURE: "TRUE", L4_INTERCEPT: "Yes"}
        core = boot(cfg, env, "core A")
        ok(f"core A up: proxy 127.0.0.1:{cfg.proxy_port}, bus {core.bus_addr}, upstream {up.base} (NOT in scope)")
        agent = BusClient.agent(core)
        op = BusClient.operator(core)

        view = agent.call("config.get", {})
        check(view["scope"]["allow_agent_widen"] is True, "config.get scope.allow_agent_widen is TRUE (file false, env `1`)")
        check(view["ca"]["allow_agent_install"] is True, "config.get ca.allow_agent_install is TRUE (file false, env `yes`)")
        gates = agent.call("l4.agent.status", {})
        check(all(gates.get(k) is True for k in L4_GATES), f"l4.agent.status: all four gates OPEN (file false; env true/1/TRUE/Yes): {gates}")

        # Under the default `auto` policy the agent is refused every Sensitive call by POLICY,
        # before any config gate -- so the gate is only observable at `all`.
        st, msg = agent.try_call("scope.add", {"host": up.authority})
        check(st == "error" and "policy" in str(msg).lower(), f"under `auto` the agent's scope.add is refused by POLICY, not the gate ({str(msg)[:90]})")
        set_policy_all(op, agent, "core A")

        tag = secrets.token_hex(4)
        st, res = active(agent, "scope.add", {"host": up.authority})
        check(st == "ok" and res == up.authority, f"the AGENT widened scope via scope.add (gate opened by env): {st} {res!r}")
        check(up.authority in agent.call("scope.list", {}), "scope.list shows the agent-added host (live guard state)")
        path = f"/env-wins-a-{tag}"
        st, fid = active(agent, "request.send", {"authority": up.authority, "path": path})
        check(st == "ok" and isinstance(fid, str) and bool(fid), f"the agent's request.send to the widened host ran (flow {fid!r})")
        check(wait_until(lambda: any(r["path"] == path for r in up.received)),
              f"GROUND TRUTH: the independent upstream RECORDED {path} -- the env-opened gate let real traffic through")

        st, res = active(agent, "l4.scope.add", L4_ENTRY)
        check(st == "ok" and isinstance(res, str) and bool(res), f"the AGENT widened the L4 scope via l4.scope.add (env opened widen): {st} {str(res)[:60]!r}")
        l4_id = res if st == "ok" else None
        listed = agent.call("l4.scope.list", {})
        mine = [e for e in listed if isinstance(e, dict) and e.get("id") == l4_id]
        check(len(mine) == 1 and mine[0].get("cidr") == L4_ENTRY["cidr"],
              f"l4.scope.list holds the runtime entry {L4_ENTRY['cidr']} (live L4 guard state): {mine}")

        check(cfg.agent_token not in json.dumps(view) and cfg.operator_token not in json.dumps(view), "no token leaked in config.get")
    finally:
        if agent is not None and l4_id:
            agent.try_call("l4.scope.remove", {"id": l4_id})
        for bus in (op, agent):
            if bus is not None:
                bus.close()
        if core is not None:
            core.stop()
        up.stop()


def leg_core_b(work: Path) -> None:
    section("CORE B: FILE opens every gate, ENV closes them -> the AGENT is REFUSED, nothing moves")
    up = Upstream().start()
    core = agent = op = None
    audit_path = work / "b-ca-audit.jsonl"
    try:
        cfg = StartConfig(
            proxy_port=free_port(), agent_token=secrets.token_hex(16), operator_token=secrets.token_hex(16),
            allow_agent_widen=True, ca_allow_agent_install=True, l4=l4_block(True),
            ca_dir=str(work / "b-ca"), ca_audit_log=str(audit_path),
        )
        env = {SCOPE_WIDEN: "0", CA_INSTALL: "false", L4_WIDEN: "no", L4_INJECT: "off", L4_CAPTURE: "0", L4_INTERCEPT: ""}
        core = boot(cfg, env, "core B")
        ok(f"core B up: proxy 127.0.0.1:{cfg.proxy_port}, bus {core.bus_addr}, upstream {up.base} (NOT in scope)")
        agent = BusClient.agent(core)
        op = BusClient.operator(core)

        view = agent.call("config.get", {})
        check(view["scope"]["allow_agent_widen"] is False, "config.get scope.allow_agent_widen is FALSE (file true, env `0`)")
        check(view["ca"]["allow_agent_install"] is False, "config.get ca.allow_agent_install is FALSE (file true, env `false`)")
        gates = agent.call("l4.agent.status", {})
        check(all(gates.get(k) is False for k in L4_GATES), f"l4.agent.status: all four gates CLOSED (file true; env no/off/0/''): {gates}")
        check(gates.get("intercept") is False, "an EMPTY env value is `set, falsy` -> closes the gate (not `unset`)")

        set_policy_all(op, agent, "core B")

        tag = secrets.token_hex(4)
        st, msg = active(agent, "scope.add", {"host": up.authority})
        check(st == "error" and "scope.allow_agent_widen" in str(msg),
              f"the agent's scope.add is REFUSED by the scope gate (env closed it): {str(msg)[:100]}")
        check(up.authority not in agent.call("scope.list", {}), "scope.list does NOT contain the host (nothing widened)")
        path = f"/env-wins-b-{tag}"
        st, msg = active(agent, "request.send", {"authority": up.authority, "path": path})
        check(st == "error" and "out of scope" in str(msg), f"the agent's request.send is refused out of scope ({str(msg)[:80]})")
        time.sleep(0.4)
        check(not any(r["path"] == path for r in up.received), "GROUND TRUTH: the upstream RECORDED NOTHING -- the env-closed gate held")

        # ca.install: only attempted once the gate is REPORTED closed (the gate reads the same
        # Config), with a private ca.dir/audit_log -- so nothing can reach the OS trust store.
        if view["ca"]["allow_agent_install"] is False:
            st, msg = active(agent, "ca.install", {})
            check(st == "error" and "refused" in str(msg) and CA_INSTALL in str(msg),
                  f"the agent's ca.install is REFUSED and the refusal names {CA_INSTALL} ({str(msg)[:80]}...)")
            check(wait_until(lambda: audit_path.is_file() and "refused" in audit_path.read_text(encoding="utf-8", errors="replace")),
                  f"the refusal was written to OUR ca.audit_log ({audit_path.name}) -- the gate ran, the OS store was never touched")
        else:
            fail("ca.allow_agent_install reported open; refusing to probe ca.install against a possibly-open gate")

        st, msg = active(agent, "l4.scope.add", L4_ENTRY)
        check(st == "error" and "widening is disabled" in str(msg),
              f"the agent's l4.scope.add is REFUSED by the L4 widen gate (env closed it): {str(msg)[:90]}")
        check(agent.call("l4.scope.list", {}) == [], "l4.scope.list stays EMPTY (deny-by-default held)")
    finally:
        for bus in (op, agent):
            if bus is not None:
                bus.close()
        if core is not None:
            core.stop()
        up.stop()


def leg_core_c(work: Path) -> None:
    section("CORE C: AITM_SCRIPTS appends LIVE scripts after the file's; AITM_SCRIPTS_STRICT=0 beats file strict:true")
    up = Upstream().start()
    core = agent = None
    try:
        fm, em = secrets.token_hex(6), secrets.token_hex(6)
        file_rhai = work / "c-file.rhai"
        env_rhai = work / "c-env.rhai"
        broken = work / "c-broken.rhai"
        file_rhai.write_text(rhai_script("e2e-file-tagger", "X-Aitm-E2e-File", fm, "file"), encoding="utf-8")
        env_rhai.write_text(rhai_script("e2e-env-tagger", "X-Aitm-E2e-Env", em, "env"), encoding="utf-8")
        broken.write_text(BROKEN_RHAI, encoding="utf-8")
        for p in (env_rhai, broken):
            if ":" in str(p):
                fail(f"temp path {p} contains ':', which AITM_SCRIPTS uses as its separator; set TMPDIR elsewhere")

        cfg = StartConfig(
            proxy_port=free_port(), agent_token=secrets.token_hex(16), operator_token=secrets.token_hex(16),
            scope_entries=[up.authority],  # the client path is scope-free; scripts see in-scope flows
            ca_dir=str(work / "c-ca"), ca_audit_log=str(work / "c-ca-audit.jsonl"),
            rhai_strict=True, scripts=[str(file_rhai)],
        )
        env = {SCRIPTS: f"{env_rhai}:{broken}", SCRIPTS_STRICT: "0"}
        core = boot(cfg, env, "core C (file strict:true + an env-added broken script)")
        ok(f"core C STARTED: AITM_SCRIPTS_STRICT=0 overrode the file's strict:true (bus {core.bus_addr})")
        agent = BusClient.agent(core)

        scripts = agent.call("script.list", {})
        names = [s.get("name") for s in scripts]
        check(names == ["e2e-file-tagger", "e2e-env-tagger"],
              f"script.list == [file script, env script] -- env entries APPENDED after the file's ({names})")
        paths = {s.get("name"): s.get("path") for s in scripts}
        check(paths.get("e2e-env-tagger") == str(env_rhai), f"the env script is the file WE named ({paths.get('e2e-env-tagger')})")
        check(all(s.get("enabled") is True for s in scripts), "both loaded scripts are enabled")
        check("e2e-broken" not in names, "the broken env script is NOT loaded (skipped under the env's strict=0)")
        # The tracing sink is `fmt()`'s default writer (stdout); the harness captures both streams.
        check(wait_until(lambda: "c-broken" in core.stdout_text() + core.stderr_text(), timeout=5.0),
              "...and it IS named in the core's log (skip-and-log, not silence)")

        path = f"/env-scripts-{secrets.token_hex(4)}"
        resp = via_proxy(cfg.proxy_port, "GET", f"{up.base}{path}")
        check(resp.status == 200, f"a REAL request through the proxy reached the upstream ({resp.status})")
        hits = [r for r in up.received if r["path"] == path]
        check(len(hits) == 1, f"the upstream RECORDED exactly that request ({len(hits)})")
        hdrs = hits[0]["headers"] if hits else {}
        check(hdrs.get("x-aitm-e2e-file") == fm, f"the FILE script's header arrived at the upstream ({hdrs.get('x-aitm-e2e-file')})")
        check(hdrs.get("x-aitm-e2e-env") == em,
              f"GROUND TRUTH: the ENV-added script's header arrived at the upstream -- it is live in the chain ({hdrs.get('x-aitm-e2e-env')})")
        check(hdrs.get("x-aitm-e2e-order") == "env",
              f"the shared header holds the ENV script's value: it ran AFTER the file's, as documented ({hdrs.get('x-aitm-e2e-order')})")
    finally:
        if agent is not None:
            agent.close()
        if core is not None:
            core.stop()
        up.stop()


def leg_attach() -> None:
    section("ATTACH: the runner's core (AITM_BUS_ADDR) reports env-over-file for every override it inherited")
    addr, tok = os.environ.get("AITM_BUS_ADDR", "").strip(), os.environ.get("AITM_BUS_TOKEN", "")
    if not (addr and tok):
        ok("no runner-provided core (AITM_BUS_ADDR/AITM_BUS_TOKEN unset); precedence was proven on the dedicated cores above")
        return
    host, port = addr.rsplit(":", 1)
    core = SimpleNamespace(bus_addr=(host.strip("[]"), int(port)),
                           cfg=SimpleNamespace(agent_token=tok, operator_token=os.environ.get("AITM_BUS_OPERATOR_TOKEN")))
    doc = None
    work = os.environ.get("AITM_E2E_WORKDIR")
    for name in ("aitm.yaml", "config.yaml"):
        p = os.path.join(work, name) if work else None
        if p and os.path.isfile(p):
            try:
                doc = json.load(open(p, encoding="utf-8"))
            except ValueError:
                doc = None
            break
    agent = BusClient.agent(core)
    try:
        view = agent.call("config.get", {})
        reported = {SCOPE_WIDEN: view["scope"]["allow_agent_widen"], CA_INSTALL: view["ca"]["allow_agent_install"]}
        filed = {}
        if doc:
            if "allow_agent_widen" in (doc.get("scope") or {}):
                filed[SCOPE_WIDEN] = doc["scope"]["allow_agent_widen"]
            if "allow_agent_install" in (doc.get("ca") or {}):
                filed[CA_INSTALL] = doc["ca"]["allow_agent_install"]
        if "l4.agent.status" in agent.tool_names():
            gates = agent.call("l4.agent.status", {})
            for key, var in L4_GATES.items():
                reported[var] = gates.get(key)
                if doc and key != "widen" and f"allow_agent_{key}" in (doc.get("l4") or {}):
                    filed[var] = doc["l4"][f"allow_agent_{key}"]
                elif doc and key == "widen" and "allow_agent_widen" in (doc.get("l4") or {}):
                    filed[var] = doc["l4"]["allow_agent_widen"]
        proven = 0
        for var, got in reported.items():
            raw = os.environ.get(var)
            if raw is not None:
                check(got == truthy(raw), f"runner core: {var}={raw!r} in env -> reported {got} (env value)")
                if var in filed and filed[var] != truthy(raw):
                    ok(f"  ...and the runner's FILE said {filed[var]}: env WON over the file on the runner's core")
                    proven += 1
            elif var in filed:
                check(got == filed[var], f"runner core: {var} unset -> reported the FILE value {filed[var]}")
            else:
                ok(f"runner core: {var} unset and not in the runner's file; reported {got} (nothing to cross-check)")
        ok(f"runner core cross-checked ({proven} file/env conflict(s) observed live)")
    finally:
        agent.close()


# ---------------------------------------------------------------------------


def main() -> int:
    binary = aitm_binary()
    if not os.path.isfile(binary):
        skip(f"aitm binary not found at {binary}: build it (cargo build -p aitm) or set AITM_BIN")
    work = Path(tempfile.mkdtemp(prefix="aitm-e2e-start-env-"))  # 0700: private CA + audit paths
    try:
        ca_dir, ca_audit = str(work / "oneshot-ca"), str(work / "oneshot-ca-audit.jsonl")
        leg_matrix(work, ca_dir, ca_audit)
        leg_strict(work, ca_dir, ca_audit)
        leg_core_a(work)
        leg_core_b(work)
        leg_core_c(work)
        leg_attach()
        ok("PASS: every documented AITM_* override won over the config file, in both directions, "
           "on the real binary and on live cores driving real traffic")
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001 -- surface boot/bus failures as a FAIL with context
        fail(f"{type(e).__name__}: {e}")
