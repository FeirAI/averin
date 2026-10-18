//! Gateway refusal records (feir-ops#1, `record_kind = gateway-refusal`).
//!
//! A refusal record says "the gateway refused this agent's attempt and recorded it". It is an ordinary
//! integrity-covered record: it carries no authority, no `extensions.broker` and no grant or use
//! evidence, so it never enters the T6 coverage closure, the D7 resource set or the taxonomy. The closed
//! vocabularies below are mirrored by `vectors/refusal-classes.v1.json` (a test pins the two together) and by
//! the server's ingest checks.
//!
//! The verifier keys on `record_kind`, never on `event_type` alone: a history that predates this kind can
//! contain a generic record with `event_type = "gateway_refusal"`, and its verdict must not change.

use crate::canon::CanonValue;
use std::collections::BTreeMap;

/// `record_kind` value of a refusal record.
pub const KIND: &str = "gateway-refusal";
/// `event_type` a refusal record must carry.
pub const EVENT_TYPE: &str = "gateway_refusal";
/// Closed set of reason classes.
pub const REASON_CLASSES: &[&str] = &[
    "not_granted",
    "policy_deny",
    "kill_fence",
    "rate_limit",
    "spend_cap",
    "cross_tenant",
    "token_unusable",
    "llm_channel_only",
    "model_unpriced",
    "modifier_unpriced",
    "provider_disabled",
    "capability_undeclared",
    "approval_unavailable",
    "decision_unavailable",
];
/// Closed set of entry points.
pub const ENTRY_POINTS: &[&str] = &["mcp", "execute", "llm", "approval_resume"];

/// Keys allowed inside `extensions.gateway_refusal`. Anything else fails closed. Every allowed key is also
/// type-checked in `check_shape` (names are a short plain identifier, timestamps the canonical form, the
/// fixed top-level markers an exact value), so a refusal can smuggle neither an object, a URL nor free text
/// through a key that is allowed.
const ALLOWED_KEYS: &[&str] = &[
    "v",
    "reason_class",
    "entry_point",
    "credential",
    "attempts",
    "first_at",
    "last_at",
    "summary",
    "by_class",
];

/// Upper bound on `attempts` (mirrors the server ingest bound).
pub const MAX_ATTEMPTS: i64 = 1_000_000_000;

/// What one shape-valid refusal record contributes to the report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Counted {
    pub attempts: u64,
    pub by_class: BTreeMap<String, u64>,
}

/// A short plain identifier: `[A-Za-z0-9._:-]{1,128}` (mirrors the server's `refusalName`).
fn is_name(s: &str) -> bool {
    (1..=128).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

/// The canonical millisecond UTC form the server writes: `YYYY-MM-DDTHH:MM:SS.mmmZ`.
fn is_canonical_time(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 24
        && b.iter().enumerate().all(|(i, c)| match i {
            4 | 7 => *c == b'-',
            10 => *c == b'T',
            13 | 16 => *c == b':',
            19 => *c == b'.',
            23 => *c == b'Z',
            _ => c.is_ascii_digit(),
        })
}

/// Whether `rec` is a refusal record (keyed on `record_kind` only).
pub fn is_refusal(rec: &CanonValue) -> bool {
    rec.get("record_kind").and_then(|v| v.as_str()) == Some(KIND)
}

fn int(v: &CanonValue) -> Option<i64> {
    match v {
        CanonValue::Int(i) => Some(*i),
        _ => None,
    }
}

/// Validate the refusal shape. `Err` is a hard verification issue (fail closed).
pub fn check_shape(rec: &CanonValue) -> Result<Counted, String> {
    if rec.get("event_type").and_then(|v| v.as_str()) != Some(EVENT_TYPE) {
        return Err(format!(
            "record_kind {KIND} requires event_type {EVENT_TYPE}"
        ));
    }
    // The server writes these constants; any other value is not a record the gateway endpoint sealed.
    if rec.get("status").and_then(|v| v.as_str()) != Some("refused") {
        return Err("a gateway refusal has status refused".into());
    }
    if rec.get("observed_via").and_then(|v| v.as_str()) != Some("gateway") {
        return Err("a gateway refusal has observed_via gateway".into());
    }
    let action_ok = rec
        .get("action")
        .and_then(|v| v.as_str())
        .is_some_and(|a| a == "*" || is_name(a));
    if !action_ok {
        return Err("a gateway refusal action must be a plain identifier or *".into());
    }
    if rec.get("authority").is_some() {
        return Err("a gateway refusal carries no authority block".into());
    }
    let ext = rec
        .get("extensions")
        .ok_or("a gateway refusal requires extensions.gateway_refusal")?;
    if ext.get("broker").is_some() || ext.get("broker_denial").is_some() {
        return Err(
            "a gateway refusal carries no extensions.broker (no grant or use evidence)".into(),
        );
    }
    let g = ext
        .get("gateway_refusal")
        .ok_or("a gateway refusal requires extensions.gateway_refusal")?;
    let members = g
        .as_object()
        .ok_or("extensions.gateway_refusal must be an object")?;
    for (k, _) in members {
        if !ALLOWED_KEYS.contains(&k.as_str()) {
            return Err(format!(
                "extensions.gateway_refusal has an unknown key {k:?}"
            ));
        }
    }
    if g.get("v").and_then(int) != Some(1) {
        return Err("extensions.gateway_refusal.v must be 1".into());
    }
    let attempts = g
        .get("attempts")
        .and_then(int)
        .filter(|n| (1..=MAX_ATTEMPTS).contains(n))
        .ok_or("extensions.gateway_refusal.attempts must be an integer in 1..=1000000000")?;
    for k in ["first_at", "last_at"] {
        if !g
            .get(k)
            .and_then(|v| v.as_str())
            .is_some_and(is_canonical_time)
        {
            return Err(format!(
                "extensions.gateway_refusal.{k} must be a canonical UTC timestamp"
            ));
        }
    }
    if let Some(c) = g.get("credential") {
        if !c.as_str().is_some_and(is_name) {
            return Err("extensions.gateway_refusal.credential must be a plain identifier".into());
        }
    }
    let summary = match g.get("summary") {
        None => false,
        Some(CanonValue::Bool(b)) => *b,
        Some(_) => return Err("extensions.gateway_refusal.summary must be a boolean".into()),
    };
    let entry = g.get("entry_point");
    if let Some(e) = entry {
        let ok = e.as_str().is_some_and(|e| ENTRY_POINTS.contains(&e));
        if !ok {
            return Err("extensions.gateway_refusal.entry_point is outside the closed set".into());
        }
    }
    let mut by_class: BTreeMap<String, u64> = BTreeMap::new();
    if summary {
        // A summary merges refusals the budget could not seal one by one: counts per class, no single class.
        if g.get("reason_class").is_some() {
            return Err("a summary refusal carries by_class, not reason_class".into());
        }
        let bc = g
            .get("by_class")
            .and_then(|v| v.as_object())
            .ok_or("a summary refusal requires by_class")?;
        let mut sum: i64 = 0;
        for (class, n) in bc {
            if !REASON_CLASSES.contains(&class.as_str()) {
                return Err(format!(
                    "by_class names a class outside the closed set: {class:?}"
                ));
            }
            let n = int(n)
                .filter(|n| (1..=MAX_ATTEMPTS).contains(n))
                .ok_or("by_class counts must be integers in 1..=1000000000")?;
            sum = sum.checked_add(n).ok_or("by_class sum overflows")?;
            by_class.insert(class.clone(), n as u64);
        }
        if sum != attempts {
            return Err("attempts must equal the sum of by_class".into());
        }
    } else {
        if entry.is_none() {
            return Err("extensions.gateway_refusal.entry_point is required".into());
        }
        if g.get("by_class").is_some() {
            return Err("by_class is only valid on a summary refusal".into());
        }
        let class = g
            .get("reason_class")
            .and_then(|v| v.as_str())
            .filter(|c| REASON_CLASSES.contains(c))
            .ok_or("extensions.gateway_refusal.reason_class is outside the closed set")?;
        by_class.insert(class.to_string(), attempts as u64);
    }
    Ok(Counted {
        attempts: attempts as u64,
        by_class,
    })
}
