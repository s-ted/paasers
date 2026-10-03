//! Adapter giving `ServeFile` bodies the `Sync` bound required by the gateway body type.
use bytes::Bytes;
use http_body::Frame;
use http_body_util::BodyExt;
use http_body_util::combinators::UnsyncBoxBody;
use std::io;
use std::pin::Pin;
use std::sync::{Mutex, PoisonError};
use std::task::{Context, Poll};

/// `ServeFile` bodies are `Send` only, the gateway body type also needs `Sync`.
/// The mutex is never contended: `poll_frame` has exclusive access (`&mut self`).
pub(super) struct SyncBody(Mutex<UnsyncBoxBody<Bytes, io::Error>>);

impl SyncBody {
    pub(super) fn new<B>(body: B) -> Self
    where
        B: http_body::Body<Data = Bytes, Error = io::Error> + Send + 'static,
    {
        Self(Mutex::new(body.boxed_unsync()))
    }
}

impl http_body::Body for SyncBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        let inner = self.get_mut().0.get_mut().unwrap_or_else(PoisonError::into_inner);
        Pin::new(inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).size_hint()
    }
}
