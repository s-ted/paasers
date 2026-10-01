//! `WatchBody`: reports errors that happen while a response body is streamed.
use crate::prelude::{Body, BoxError};
use bytes::Bytes;
use http_body::Frame;
use std::pin::Pin;
use std::task::{Context, Poll};

type OnError = Box<dyn FnOnce(String) + Send + Sync>;

pin_project_lite::pin_project! {
    pub struct WatchBody {
        #[pin]
        inner: Body,
        on_error: Option<OnError>,
    }
}

impl WatchBody {
    pub fn new(inner: Body, f: OnError) -> Self {
        Self {
            inner,
            on_error: Some(f),
        }
    }
}

impl http_body::Body for WatchBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = self.project();
        let r = this.inner.poll_frame(cx);
        if let Poll::Ready(Some(Err(e))) = &r
            && let Some(f) = this.on_error.take()
        {
            f(e.to_string());
        }
        r
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::{BodyExt, StreamBody};
    use std::sync::{Arc, Mutex};

    #[tokio::test]
    async fn records_error_once() {
        let frames: Vec<Result<Frame<Bytes>, BoxError>> = vec![
            Ok(Frame::data(Bytes::from_static(b"x"))),
            Err("cut".into()),
            Err("again".into()),
        ];
        let inner = StreamBody::new(futures_util::stream::iter(frames)).boxed();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s2 = seen.clone();
        let mut b = WatchBody::new(inner, Box::new(move |m| s2.lock().unwrap().push(m)));
        assert!(b.frame().await.unwrap().is_ok());
        assert!(b.frame().await.unwrap().is_err());
        assert!(b.frame().await.unwrap().is_err());
        assert_eq!(*seen.lock().unwrap(), vec!["cut".to_string()]);
    }
}
