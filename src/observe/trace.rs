//! W3C `traceparent` parsing and generation.
use crate::prelude::TraceCtx;
use fastrace::collector::{SpanContext, SpanId, TraceId};

// fastrace `random()` can return 0 (invalid per W3C), so ids are generated here.
pub fn nz128() -> u128 {
    rand::random::<u128>().max(1)
}

pub fn nz64() -> u64 {
    rand::random::<u64>().max(1)
}

/// Reads `traceparent`: a valid header reuses its trace id, otherwise a new one is generated.
pub fn from_headers(h: &http::HeaderMap) -> TraceCtx {
    let incoming = h
        .get("traceparent")
        .and_then(|v| v.to_str().ok())
        .and_then(SpanContext::decode_w3c_traceparent);
    let span_id = nz64();
    match incoming {
        Some(sc) => TraceCtx {
            trace_id: sc.trace_id.0,
            parent_span: Some(sc.span_id.0),
            span_id,
            sampled: sc.sampled,
        },
        None => TraceCtx {
            trace_id: nz128(),
            parent_span: None,
            span_id,
            sampled: true,
        },
    }
}

pub fn traceparent(t: &TraceCtx) -> String {
    SpanContext::new(TraceId(t.trace_id), SpanId(t.span_id))
        .sampled(t.sampled)
        .encode_w3c_traceparent()
}

/// 32 lowercase hex characters, used as the Incident ID.
pub fn trace_hex(id: u128) -> String {
    format!("{id:032x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(v: &str) -> http::HeaderMap {
        let mut h = http::HeaderMap::new();
        h.insert("traceparent", http::HeaderValue::from_str(v).unwrap());
        h
    }

    #[test]
    fn reuses_valid_incoming_trace_id() {
        let t = from_headers(&headers(
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        ));
        assert_eq!(trace_hex(t.trace_id), "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(t.parent_span, Some(0x00f0_67aa_0ba9_02b7));
        assert_ne!(t.span_id, 0);
    }

    #[test]
    fn generates_when_absent() {
        let t = from_headers(&http::HeaderMap::new());
        assert!(t.trace_id != 0 && t.parent_span.is_none() && t.sampled);
    }

    #[test]
    fn rejects_invalid_version_zero_ids_garbage() {
        for bad in [
            "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
            "garbage",
            "",
        ] {
            let t = from_headers(&headers(bad));
            assert!(t.parent_span.is_none(), "{bad}");
        }
    }

    #[test]
    fn encode_roundtrip() {
        let t = from_headers(&http::HeaderMap::new());
        let tp = traceparent(&t);
        assert_eq!(tp.len(), 55);
        let back = from_headers(&headers(&tp));
        assert_eq!(back.trace_id, t.trace_id);
        assert_eq!(back.parent_span, Some(t.span_id));
    }
}
