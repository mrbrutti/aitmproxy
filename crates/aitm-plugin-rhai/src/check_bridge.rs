//! The `reg.add_check(meta, closure)` bridge and [`ScriptCheck`] (plan Task 13):
//! a Rhai check declares its `CheckMeta` and verdict closure here and becomes a
//! native `Check` the scanner engine schedules.
//!
//! **One catalogue, two languages.** A script's check is the same thing to the
//! scheduler as a Rust one: it carries a full [`CheckMeta`] and returns a
//! [`Verdict`]. That is why missing or invalid meta is a **load error naming the
//! key** rather than a default — the catalogue cannot schedule what it cannot
//! classify (spec D4).
//!
//! **What a closure may return.** A verdict map with the `Verdict` wire keys, a
//! plain string, which reads as `inconclusive` with that string as the detail,
//! or an **array of verdict maps**: the first is the root verdict and the rest
//! are its `more` siblings, each map optionally carrying `location: #{ path,
//! name }` so an origin-scoped check yields one issue per exposed path
//! (coordinator item (g)). The string form is what keeps an old-style script
//! honest: a check that only prints a sentence still produces a legal verdict
//! instead of breaking the run. A closure that throws is an `error` verdict
//! carrying the script error — a check never fails the job (spec D2).
//!
//! **Where its probes go.** `run` opens a [`RunKind::Check`] run under the
//! profile's `check_timeout`, parks the host in the [`crate::host_probe`] check
//! context so `probe.*` resolves, and — when the host lends its client — runs the
//! call inside [`with_client`] so a closure's `http.send` is budgeted, paced,
//! marked and recorded by the job exactly like a `probe.send` (spec D9.3).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use aitm_core::{CallerTrust, Value};
use aitm_scan_model::check::{CheckMeta, ControlHint, Evidence, PocHint, Verdict, VerdictLocation};
use aitm_scan_model::point::InsertionPoint;
use aitm_scan_model::traits::{Check, ProbeHost};
use aitm_scan_model::vocab::{CheckOrigin, Confidence, Outcome};
use rhai::{CallFnOptions, Dynamic, Engine, FnPtr, Map, Scope, AST};

use crate::engine::{begin_run, blocking, enter_constants, Budget, RunKind};
use crate::error::ScriptError;
use crate::host_core::Options;
use crate::host_net::with_client;
use crate::host_probe::{self, CheckCtx};
use crate::host_registry::seed_call_context;
use crate::marshal::dynamic_to_value;

/// The keys a check's meta map may carry: exactly [`CheckMeta`]'s wire names
/// minus `origin`, which the bridge supplies from where the script came from.
/// A key outside this set is a typo the author must see, not a silent no-op.
const META_KEYS: [&str; 17] = [
    "id",
    "name",
    "class",
    "lanes",
    "kinds",
    "intensity",
    "cost",
    "technique",
    "severity",
    "confidence_max",
    "needs_baseline",
    "wants_traits",
    "targets_session",
    "scope",
    "cwe",
    "description",
    "remediation",
];

/// The keys a verdict map may carry. `more` is not one: siblings are expressed
/// by returning an array, never nested inside a map.
const VERDICT_KEYS: [&str; 6] = [
    "outcome",
    "confidence",
    "evidence",
    "detail",
    "poc_hint",
    "location",
];

/// The keys a verdict's `location` map may carry: the [`VerdictLocation`] fields.
const LOCATION_KEYS: [&str; 2] = ["path", "name"];

/// A check a script declared with `reg.add_check(meta, |point| …)`.
///
/// Holds the same engine, AST, options and budget as the script's hooks and
/// commands, so a check sees the host surface its author tested against.
pub struct ScriptCheck {
    meta: CheckMeta,
    engine: Arc<Engine>,
    ast: Arc<AST>,
    func: FnPtr,
    /// Passed as the call's tag so `option(name)` works inside a check.
    options: Options,
    /// The script's configured run budget; `run` widens the wall-clock to the
    /// profile's `check_timeout` ([`Budget::for_check`]).
    budget: Budget,
    /// The script that declared it, for error messages.
    script: String,
}

impl ScriptCheck {
    /// A check over `func`, carrying the already-validated `meta`.
    pub fn new(
        meta: CheckMeta,
        engine: Arc<Engine>,
        ast: Arc<AST>,
        func: FnPtr,
        options: Options,
        budget: Budget,
        script: String,
    ) -> Self {
        Self {
            meta,
            engine,
            ast,
            func,
            options,
            budget,
            script,
        }
    }
}

impl Check for ScriptCheck {
    fn meta(&self) -> &CheckMeta {
        &self.meta
    }

    /// Call the script's closure with the point map and read its verdict.
    ///
    /// The body is synchronous inside [`blocking`] — rhai is a synchronous
    /// engine and every probe it makes drives its own future — so the returned
    /// future resolves on the first poll without holding an await point across
    /// any rhai value.
    fn run<'a>(
        &'a self,
        point: &'a InsertionPoint,
        host: &'a dyn ProbeHost,
    ) -> Pin<Box<dyn Future<Output = Verdict> + Send + 'a>> {
        Box::pin(async move {
            // The bridge parks an *owning* handle in the thread-local, so the
            // host must be able to lend one (plan call B5). A host that cannot
            // is a wiring bug in the engine, not a finding about the target.
            let Some(shared) = host.shared() else {
                return error_verdict(
                    "the engine must hand a shared probe host to a script check \
                     (ProbeHost::shared returned none)",
                );
            };
            // The same holds for the client: a closure's `http.send` must go
            // through the job's budgeted client (spec D9.3), so a host that
            // lends none is the same wiring bug, and nothing runs on the
            // unbudgeted namespace client in its place.
            let Some(client) = host.client() else {
                return error_verdict(
                    "the engine must hand a budgeted client to a script check \
                     (ProbeHost::client returned none)",
                );
            };
            let check_timeout = Duration::from_secs(host.profile().budget.check_timeout_s);
            // A closure that names anything outside itself — `probe`, a script
            // constant — is curried by rhai with those values, so the call must
            // lead with the curry and end with the point, exactly as a script
            // command's invocation does. Passing the point alone makes rhai
            // report the closure as "function not found" on the arity.
            let mut args = self.func.curry().to_vec();
            args.push(Dynamic::from_map(point_map(point)));

            // The per-check wall budget (the profile's `check_timeout`), not the
            // 2 s hook budget: a timing probe must be able to wait out a
            // server-side delay without aborting the run (spec D4).
            let budget = Budget::for_check(self.budget, check_timeout);

            blocking(move || {
                let _run = begin_run(RunKind::Check, budget);
                // A check runs detached from any frontend, on behalf of a job an
                // agent may have started: the least-privileged `Agent` trust, as
                // every other unattended boundary seeds (never widened here).
                let _seed = seed_call_context(
                    CallerTrust::Agent,
                    Some(self.options.to_value()),
                    self.ast.source().map(str::to_string),
                );
                let _constants = enter_constants(&self.ast);
                let _ctx = host_probe::enter(CheckCtx {
                    host: shared,
                    point: point.clone(),
                });

                let call = move || {
                    self.engine.call_fn_with_options::<Dynamic>(
                        CallFnOptions::new(),
                        &mut Scope::new(),
                        &self.ast,
                        self.func.fn_name(),
                        args,
                    )
                };
                // Inside a job the closure's own `http.send` goes through the
                // job's client, so scope, rate, marks and the record policy
                // apply to a script's sends too (spec D9.3).
                let result = with_client(client, call);

                match result {
                    Ok(value) => verdict_from_dynamic(&value),
                    Err(err) => error_verdict(
                        ScriptError::from_eval(&self.script, self.func.fn_name(), &err, &budget)
                            .to_string(),
                    ),
                }
            })
        })
    }
}

/// The map a check closure receives: the D4 keys, and nothing a check has no
/// business reading. An absent `path`/`url`/`method`/`example` is `()`.
fn point_map(point: &InsertionPoint) -> Map {
    let mut map = Map::new();
    map.insert(
        "kind".into(),
        Dynamic::from(json_token(serde_json::to_value(point.kind))),
    );
    map.insert("name".into(), Dynamic::from(point.name.clone()));
    map.insert("path".into(), optional_text(point.path.as_deref()));
    map.insert("url".into(), optional_text(point.url.as_deref()));
    map.insert("method".into(), optional_text(point.method.as_deref()));
    map.insert("example".into(), optional_text(point.example.as_deref()));
    map.insert(
        "traits".into(),
        Dynamic::from_array(
            point
                .traits
                .iter()
                .map(|t| Dynamic::from(json_token(serde_json::to_value(t))))
                .collect(),
        ),
    );
    map
}

/// A vocabulary value as the string a script reads, taken from its own wire
/// form so the script vocabulary and the bus vocabulary can never drift.
fn json_token(value: Result<serde_json::Value, serde_json::Error>) -> String {
    value
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

/// `Some(text)` as a Rhai string, `None` as `()`.
fn optional_text(text: Option<&str>) -> Dynamic {
    match text {
        Some(text) => Dynamic::from(text.to_string()),
        None => Dynamic::UNIT,
    }
}

/// Build a [`CheckMeta`] from a script's meta map, naming the offending key when
/// it cannot (spec D4). `origin` is supplied by the bridge from where the script
/// came from; a script that declares its own `origin` is refused on that key,
/// because a script may not claim to be `native` or `bundled`.
///
/// Returns `Err((key, message))`; the caller wraps it in
/// [`ScriptError::CheckMeta`] with the script's name.
pub fn meta_from_map(map: &Map, origin: CheckOrigin) -> Result<CheckMeta, (String, String)> {
    if map.contains_key("origin") {
        return Err((
            "origin".to_string(),
            "a script does not declare its own origin; aitm records where the script came from"
                .to_string(),
        ));
    }
    if let Some(unknown) = map.keys().find(|k| !META_KEYS.contains(&k.as_str())) {
        return Err((
            unknown.to_string(),
            format!(
                "not a check metadata key; the keys are {}",
                META_KEYS.join(", ")
            ),
        ));
    }

    let mut object = json_object(map).map_err(|err| ("meta".to_string(), err))?;
    object.insert(
        "origin".to_string(),
        serde_json::to_value(&origin).map_err(|err| ("origin".to_string(), err.to_string()))?,
    );

    serde_json::from_value::<CheckMeta>(serde_json::Value::Object(object.clone()))
        .map_err(|err| (offending_key(&object, &err), err.to_string()))
}

/// Which key a failed `CheckMeta` parse is about: the one serde named as
/// missing, else the first present key whose value does not parse into its own
/// field's type, else the map as a whole.
fn offending_key(
    object: &serde_json::Map<String, serde_json::Value>,
    err: &dyn ToString,
) -> String {
    let message = err.to_string();
    if let Some(rest) = message.strip_prefix("missing field `") {
        if let Some(key) = rest.split('`').next() {
            return key.to_string();
        }
    }
    for (key, value) in object {
        if !field_parses(key, value) {
            return key.clone();
        }
    }
    "meta".to_string()
}

/// Whether one meta value parses into the type its field has. The table is the
/// `CheckMeta` field list; a key not in it has already been refused above.
fn field_parses(key: &str, value: &serde_json::Value) -> bool {
    use aitm_scan_model::vocab::{
        CheckCost, CheckScope, Confidence as Conf, InsertionKind, Intensity, LaneKind, PointTrait,
        Technique,
    };

    let value = value.clone();
    match key {
        "id" | "name" | "class" | "description" => serde_json::from_value::<String>(value).is_ok(),
        "remediation" => serde_json::from_value::<Option<String>>(value).is_ok(),
        "lanes" => serde_json::from_value::<Vec<LaneKind>>(value).is_ok(),
        "kinds" => serde_json::from_value::<Vec<InsertionKind>>(value).is_ok(),
        "intensity" => serde_json::from_value::<Intensity>(value).is_ok(),
        "cost" => serde_json::from_value::<CheckCost>(value).is_ok(),
        "technique" => serde_json::from_value::<Technique>(value).is_ok(),
        "severity" => serde_json::from_value::<aitm_poc::Severity>(value).is_ok(),
        "confidence_max" => serde_json::from_value::<Conf>(value).is_ok(),
        "needs_baseline" | "targets_session" => serde_json::from_value::<bool>(value).is_ok(),
        "wants_traits" => serde_json::from_value::<Option<Vec<PointTrait>>>(value).is_ok(),
        "scope" => serde_json::from_value::<CheckScope>(value).is_ok(),
        "cwe" => serde_json::from_value::<Option<u32>>(value).is_ok(),
        "origin" => serde_json::from_value::<CheckOrigin>(value).is_ok(),
        _ => false,
    }
}

/// A rhai map as a JSON object, through the bus `Value` the rest of the tier
/// marshals with (the model crate has no rhai dependency).
fn json_object(map: &Map) -> Result<serde_json::Map<String, serde_json::Value>, String> {
    let value = dynamic_to_value(&Dynamic::from_map(map.clone())).map_err(|err| err.to_string())?;
    match value_to_json(&value) {
        serde_json::Value::Object(object) => Ok(object),
        other => Err(format!("expected a map, got {other}")),
    }
}

/// `aitm_core::Value` as `serde_json::Value`. Bytes become a string: a script's
/// meta and verdict maps are text, and a blob in one is an author error the
/// typed parse below reports on its own key.
fn value_to_json(value: &Value) -> serde_json::Value {
    match value {
        Value::Null => serde_json::Value::Null,
        Value::Bool(b) => serde_json::Value::Bool(*b),
        Value::Int(i) => serde_json::Value::from(*i),
        Value::Float(f) => serde_json::Number::from_f64(*f)
            .map(serde_json::Value::Number)
            .unwrap_or(serde_json::Value::Null),
        Value::Str(s) => serde_json::Value::String(s.clone()),
        Value::Bytes(b) => serde_json::Value::String(String::from_utf8_lossy(b).to_string()),
        Value::Array(items) => serde_json::Value::Array(items.iter().map(value_to_json).collect()),
        Value::Object(fields) => serde_json::Value::Object(
            fields
                .iter()
                .map(|(k, v)| (k.clone(), value_to_json(v)))
                .collect(),
        ),
    }
}

/// Read a closure's return value as a [`Verdict`] (spec D4).
///
/// A map is read key by key; a plain string is `inconclusive` with that string
/// as the detail, so a script that only says what it saw still produces a legal
/// verdict; an array of maps is the root verdict followed by its `more`
/// siblings ([`verdict_from_array`]); anything else is an `error` naming what
/// came back.
pub fn verdict_from_dynamic(value: &Dynamic) -> Verdict {
    if let Some(text) = value.read_lock::<rhai::ImmutableString>() {
        return Verdict {
            outcome: Outcome::Inconclusive,
            confidence: Confidence::Tentative,
            evidence: Evidence::default(),
            detail: text.to_string(),
            poc_hint: None,
            location: None,
            more: Vec::new(),
        };
    }
    if let Some(items) = value.read_lock::<rhai::Array>() {
        return verdict_from_array(&items);
    }
    let Some(map) = value.read_lock::<Map>() else {
        return error_verdict(format!(
            "a check closure returns a verdict map, a string or an array of verdict maps, \
             got a {}",
            value.type_name()
        ));
    };
    verdict_from_map(&map)
}

/// An array return: element `[0]` is the root verdict, the rest go into its
/// `more`, each read by the map rule. A non-map element refuses the whole
/// array — the root is an `error` naming the index — because a half-read list
/// of paths would report some exposures and silently drop others. The bridge
/// nests one level only: a map cannot carry `more` (it is not a verdict key),
/// so nothing deeper can be expressed.
fn verdict_from_array(items: &[Dynamic]) -> Verdict {
    let mut verdicts = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let Some(map) = item.read_lock::<Map>() else {
            return error_verdict(format!(
                "a verdict array holds verdict maps only; element [{index}] is a {}",
                item.type_name()
            ));
        };
        verdicts.push(verdict_from_map(&map));
    }
    let mut rest = verdicts.into_iter();
    let Some(mut root) = rest.next() else {
        return error_verdict(
            "a check closure returned an empty array; return a verdict map, a string, \
             or an array with at least one verdict map",
        );
    };
    root.more = rest.collect();
    root
}

/// The map rule: one verdict map, key by key, unknown keys refused by name.
fn verdict_from_map(map: &Map) -> Verdict {
    if let Some(unknown) = map.keys().find(|k| !VERDICT_KEYS.contains(&k.as_str())) {
        return error_verdict(format!(
            "a verdict has no field '{unknown}'; the fields are {}",
            VERDICT_KEYS.join(", ")
        ));
    }

    let outcome = match map.get("outcome").map(token) {
        Some(Some(token)) => match serde_json::from_value::<Outcome>(token.clone().into()) {
            Ok(outcome) => outcome,
            Err(_) => {
                return error_verdict(format!(
                    "`{token}` is not an outcome; the outcomes are vulnerable, clean, \
                     inconclusive, error"
                ))
            }
        },
        _ => {
            return error_verdict(
                "a verdict map needs an `outcome` of vulnerable, clean, inconclusive or error",
            )
        }
    };

    let confidence = match map.get("confidence").map(token) {
        None | Some(None) => Confidence::Tentative,
        Some(Some(token)) => match serde_json::from_value::<Confidence>(token.clone().into()) {
            Ok(confidence) => confidence,
            Err(_) => {
                return error_verdict(format!(
                    "`{token}` is not a confidence; they are tentative, firm, certain"
                ))
            }
        },
    };

    let mut evidence = Evidence::default();
    if let Some(value) = map.get("evidence").filter(|v| !v.is_unit()) {
        let Some(fields) = value.read_lock::<Map>() else {
            return error_verdict("a verdict's `evidence` must be a map of payload and matched");
        };
        evidence.payload = fields.get("payload").and_then(token);
        // Bounded by the model: the script chooses what matched, never how much
        // of it an issue carries.
        evidence.matched = fields
            .get("matched")
            .and_then(token)
            .map(|text| Evidence::excerpt(&text));
    }

    let poc_hint = match map.get("poc_hint").filter(|v| !v.is_unit()) {
        None => None,
        Some(value) => {
            let Some(fields) = value.read_lock::<Map>() else {
                return error_verdict("a verdict's `poc_hint` must be a map");
            };
            match poc_hint_from_map(&fields) {
                Ok(hint) => Some(hint),
                Err(err) => return error_verdict(format!("poc_hint: {err}")),
            }
        }
    };

    let location = match map.get("location").filter(|v| !v.is_unit()) {
        None => None,
        Some(value) => {
            let Some(fields) = value.read_lock::<Map>() else {
                return error_verdict("a verdict's `location` must be a map of path and name");
            };
            if let Some(unknown) = fields.keys().find(|k| !LOCATION_KEYS.contains(&k.as_str())) {
                return error_verdict(format!(
                    "a verdict's `location` has no field '{unknown}'; the fields are {}",
                    LOCATION_KEYS.join(", ")
                ));
            }
            Some(VerdictLocation {
                path: fields.get("path").and_then(token),
                name: fields.get("name").and_then(token),
            })
        }
    };

    Verdict {
        outcome,
        confidence,
        evidence,
        detail: map.get("detail").and_then(token).unwrap_or_default(),
        poc_hint,
        location,
        // Siblings come only from the array form; a map is one verdict.
        more: Vec::new(),
    }
}

/// Build a [`PocHint`] from a verdict's `poc_hint` map: `matchers` in the PoC
/// YAML vocabulary the PoC loader already parses (a list is an implicit `all`),
/// and an optional benign `control` whose response must *not* look vulnerable.
pub fn poc_hint_from_map(map: &Map) -> Result<PocHint, String> {
    let assertions = vec![assertion_from(map.get("matchers"), "matchers")?];

    let control = match map.get("control").filter(|v| !v.is_unit()) {
        None => None,
        Some(value) => {
            let fields = value
                .read_lock::<Map>()
                .ok_or("`control` must be a map of payload and matchers")?;
            let payload = fields
                .get("payload")
                .and_then(token)
                .ok_or("`control` needs a `payload`")?;
            Some(ControlHint {
                payload,
                expect: vec![assertion_from(fields.get("matchers"), "control.matchers")?],
            })
        }
    };

    Ok(PocHint {
        assertions,
        control,
    })
}

/// Parse one `matchers` list through `aitm_poc::Assertion`'s own deserializer,
/// so a hint speaks exactly the vocabulary a PoC file does (`type: status |
/// word | regex | dsl`, and `all`/`any`/`not`). A list parses as `all`.
fn assertion_from(value: Option<&Dynamic>, what: &str) -> Result<aitm_poc::Assertion, String> {
    let value = value
        .filter(|v| !v.is_unit())
        .ok_or_else(|| format!("`{what}` is required and must be a list of matchers"))?;
    let json = value_to_json(&dynamic_to_value(value).map_err(|err| err.to_string())?);
    if !json.is_array() {
        return Err(format!("`{what}` must be a list of matchers"));
    }
    serde_json::from_value::<aitm_poc::Assertion>(json).map_err(|err| format!("`{what}`: {err}"))
}

/// A Rhai value as the text a token-valued field needs; `None` for `()`.
fn token(value: &Dynamic) -> Option<String> {
    if value.is_unit() {
        return None;
    }
    value
        .read_lock::<rhai::ImmutableString>()
        .map(|text| text.to_string())
}

/// The verdict a check that could not run produces. `error` is not a finding:
/// it tells the engine this check concluded nothing and why (spec D2).
fn error_verdict(detail: impl Into<String>) -> Verdict {
    Verdict {
        outcome: Outcome::Error,
        confidence: Confidence::Tentative,
        evidence: Evidence::default(),
        detail: detail.into(),
        poc_hint: None,
        location: None,
        more: Vec::new(),
    }
}

/// Convert every check a script's `load(reg)` collected, in declaration order.
///
/// All or nothing: the first bad meta is a [`ScriptError::CheckMeta`] naming the
/// script, the check and the key, and no check from that script is registered —
/// a half-registered catalogue is worse than a refused script.
pub(crate) fn checks_from_collected(
    collected: Vec<(Map, FnPtr)>,
    origin: &CheckOrigin,
    engine: &Arc<Engine>,
    ast: &Arc<AST>,
    options: &Options,
    budget: Budget,
    script: &str,
) -> Result<Vec<Arc<dyn Check>>, ScriptError> {
    let mut checks: Vec<Arc<dyn Check>> = Vec::with_capacity(collected.len());
    for (map, func) in collected {
        let meta = meta_from_map(&map, origin.clone()).map_err(|(key, message)| {
            ScriptError::CheckMeta {
                script: script.to_string(),
                check: declared_id(&map),
                key,
                message,
            }
        })?;
        checks.push(Arc::new(ScriptCheck::new(
            meta,
            Arc::clone(engine),
            Arc::clone(ast),
            func,
            options.clone(),
            budget,
            script.to_string(),
        )));
    }
    Ok(checks)
}

/// The `id` the map declared, when it declared a string one — for the error of a
/// check that failed on some *other* key.
fn declared_id(map: &Map) -> Option<String> {
    map.get("id").and_then(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// T3 live-run bug (coordinator, 2026-11-01): `META_KEYS` is the set a
    /// script may declare, and it must be every `CheckMeta` wire key but
    /// `origin` — the bridge once omitted `remediation` and refused every script
    /// that documented a fix. Pinned against the struct's own serialisation so
    /// a field added to `CheckMeta` fails here rather than in a script.
    #[test]
    fn meta_keys_cover_every_check_meta_field_but_origin() {
        let json = serde_json::to_value(aitm_scan_model::testing::null_meta("pin"))
            .expect("CheckMeta serialises");
        let mut wire: Vec<String> = json
            .as_object()
            .expect("an object")
            .keys()
            .filter(|k| k.as_str() != "origin")
            .cloned()
            .collect();
        wire.sort();
        let mut keys: Vec<String> = META_KEYS.iter().map(|k| k.to_string()).collect();
        keys.sort();
        assert_eq!(keys, wire);
        assert!(META_KEYS.contains(&"remediation"));

        // `field_parses` is a typed arm per key, so it cannot consume the list
        // directly; pin instead that every key the bridge accepts has an arm
        // that parses the field's own serialised value.
        for key in META_KEYS {
            assert!(
                field_parses(key, &json[key]),
                "field_parses has no working arm for `{key}`"
            );
        }
    }
}
