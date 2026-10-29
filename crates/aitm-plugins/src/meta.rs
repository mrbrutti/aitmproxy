//! The meta plugin (F6): per-flow annotations over the flow store.
//!
//! `flow.mark` replaces a flow's mark set (the highlight colours an operator
//! assigns); `flow.comment` sets or clears its free-text comment. Both edit
//! `FlowMeta` fields that already exist on every flow — the store carried them,
//! but no command reached them until now. Neither touches the network.

use std::sync::Arc;

use aitm_core::{
    Command, CommandHost, Flow, FlowId, ParamDef, ParamSchema, Params, Plugin, Registry, TypeDesc,
    Value,
};

/// Registers `flow.mark` and `flow.comment`. Observes no events.
pub struct MetaPlugin;

impl MetaPlugin {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MetaPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl Plugin for MetaPlugin {
    fn name(&self) -> &str {
        "meta"
    }

    fn load(&mut self, reg: &mut Registry) {
        reg.add_command(Arc::new(FlowMark));
        reg.add_command(Arc::new(FlowComment));
    }
}

fn id_param(description: &str) -> ParamDef {
    ParamDef {
        name: "id".into(),
        ty: TypeDesc::FlowId,
        required: true,
        description: description.into(),
    }
}

/// Refuse up front when the flow is unknown, so a mistyped id is a clear error
/// rather than a silently dropped update.
fn require_flow(host: &CommandHost, id: FlowId) -> anyhow::Result<()> {
    host.store()
        .get(id)
        .map(|_| ())
        .ok_or_else(|| anyhow::anyhow!("no flow with id {id}"))
}

/// Bound the mark set so it cannot grow the store without limit or carry control
/// characters into a surface: at most 32 marks, each at most 64 bytes, no control
/// characters (a mark is a short colour/label token).
const MAX_MARKS: usize = 32;
const MAX_MARK_BYTES: usize = 64;
const MAX_COMMENT_BYTES: usize = 4096;

fn validate_marks(marks: &[String]) -> anyhow::Result<()> {
    if marks.len() > MAX_MARKS {
        anyhow::bail!("at most {MAX_MARKS} marks (got {})", marks.len());
    }
    for m in marks {
        if m.len() > MAX_MARK_BYTES {
            anyhow::bail!("each mark is at most {MAX_MARK_BYTES} bytes");
        }
        if m.chars().any(char::is_control) {
            anyhow::bail!("a mark must not contain control characters");
        }
    }
    Ok(())
}

/// Bound the comment at 4 KiB and reject control characters other than tab and
/// newline, so a comment cannot bloat memory or smuggle escape sequences.
fn validate_comment(text: &str) -> anyhow::Result<()> {
    if text.len() > MAX_COMMENT_BYTES {
        anyhow::bail!(
            "comment is at most {MAX_COMMENT_BYTES} bytes (got {})",
            text.len()
        );
    }
    if text
        .chars()
        .any(|c| c.is_control() && c != '\n' && c != '\t')
    {
        anyhow::bail!("comment must not contain control characters other than tab and newline");
    }
    Ok(())
}

/// `flow.mark {id, marks}` → replace a flow's mark set; returns the new set.
struct FlowMark;

impl Command for FlowMark {
    fn name(&self) -> &str {
        "flow.mark"
    }

    fn sensitivity(&self) -> aitm_core::Sensitivity {
        aitm_core::Sensitivity::Write
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Replace a flow's highlight mark set (e.g. colour names); an empty \
                          array clears it."
                .into(),
            params: vec![
                id_param("The flow to mark."),
                ParamDef {
                    name: "marks".into(),
                    ty: TypeDesc::Array(Box::new(TypeDesc::Str)),
                    required: true,
                    description: "The marks to set; replaces any existing marks.".into(),
                },
            ],
            result: TypeDesc::Array(Box::new(TypeDesc::Str)),
        }
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        let id = args.get_flow_id("id")?;
        let marks = match args.get("marks") {
            Some(Value::Array(items)) => items
                .iter()
                .map(|v| match v {
                    Value::Str(s) => Ok(s.clone()),
                    other => anyhow::bail!("each mark must be a string, got {other:?}"),
                })
                .collect::<anyhow::Result<Vec<String>>>()?,
            Some(other) => anyhow::bail!("param `marks` must be an array, got {other:?}"),
            None => anyhow::bail!("missing required param `marks`"),
        };
        validate_marks(&marks)?;
        require_flow(host, id)?;
        let to_store = marks.clone();
        host.store().update(id, &mut |flow: &mut Flow| {
            flow.metadata_mut().marks = to_store.clone();
        });
        Ok(Value::Array(marks.into_iter().map(Value::Str).collect()))
    }
}

/// `flow.comment {id, text}` → set (or clear, with `""`) a flow's comment.
struct FlowComment;

impl Command for FlowComment {
    fn name(&self) -> &str {
        "flow.comment"
    }

    fn sensitivity(&self) -> aitm_core::Sensitivity {
        aitm_core::Sensitivity::Write
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Set a flow's free-text comment; an empty string clears it.".into(),
            params: vec![
                id_param("The flow to comment on."),
                ParamDef {
                    name: "text".into(),
                    ty: TypeDesc::Str,
                    required: true,
                    description: "The comment text; empty clears the comment.".into(),
                },
            ],
            result: TypeDesc::Str,
        }
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        let id = args.get_flow_id("id")?;
        let text = args.get_str("text")?.to_string();
        validate_comment(&text)?;
        require_flow(host, id)?;
        let comment = if text.is_empty() { None } else { Some(text) };
        let to_store = comment.clone();
        host.store().update(id, &mut |flow: &mut Flow| {
            flow.metadata_mut().comment = to_store.clone();
        });
        Ok(comment.map_or(Value::Null, Value::Str))
    }
}
