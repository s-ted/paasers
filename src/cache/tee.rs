//! `TeeBody`: copies a streamed body into a bounded buffer and reports it when complete.
use crate::prelude::{Body, BoxError};
use bytes::{Bytes, BytesMut};
use http_body::Frame;
use std::pin::Pin;
use std::task::{Context, Poll};

type OnDone = Box<dyn FnOnce(Bytes) + Send + Sync>;

pin_project_lite::pin_project! {
    pub struct TeeBody {
        #[pin]
        inner: Body,
        buf: Option<BytesMut>,
        limit: usize,
        on_done: Option<OnDone>,
    }
}

impl TeeBody {
    pub fn new(inner: Body, limit: usize, on_done: OnDone) -> Self {
        Self {
            inner,
            buf: Some(BytesMut::new()),
            limit,
            on_done: Some(on_done),
        }
    }
}

impl http_body::Body for TeeBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let mut this = self.project();
        let res = this.inner.as_mut().poll_frame(cx);
        match &res {
            Poll::Ready(Some(Ok(f))) => {
                if let Some(d) = f.data_ref() {
                    let over = this.buf.as_ref().is_some_and(|b| b.len() + d.len() > *this.limit);
                    if over {
                        *this.buf = None;
                    } else if let Some(b) = this.buf.as_mut() {
                        b.extend_from_slice(d);
                    }
                }
            }
            Poll::Ready(Some(Err(_))) => *this.buf = None,
            Poll::Ready(None) | Poll::Pending => {}
        }
        // hyper stops polling as soon as `is_end_stream()` is true, so finalize here too.
        let done = matches!(res, Poll::Ready(None))
            || (matches!(res, Poll::Ready(Some(Ok(_)))) && this.inner.is_end_stream());
        if done && let (Some(b), Some(f)) = (this.buf.take(), this.on_done.take()) {
            f(b.freeze());
        }
        res
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
    use crate::prelude::full;
    use http_body_util::{BodyExt, StreamBody};
    use std::sync::{Arc, Mutex};

    type Captured = Arc<Mutex<Vec<Bytes>>>;

    fn capture() -> (Captured, OnDone) {
        let c: Captured = Arc::default();
        let c2 = c.clone();
        (c, Box::new(move |b| c2.lock().unwrap().push(b)))
    }

    fn stream(frames: Vec<Result<Frame<Bytes>, BoxError>>) -> Body {
        StreamBody::new(futures_util::stream::iter(frames)).boxed()
    }

    #[tokio::test]
    async fn collects_streamed_body_once() {
        let (c, f) = capture();
        let body = stream(vec![Ok(Frame::data("ab".into())), Ok(Frame::data("cd".into()))]);
        let out = TeeBody::new(body, 100, f).collect().await.unwrap().to_bytes();
        assert_eq!(&out[..], b"abcd");
        assert_eq!(*c.lock().unwrap(), vec![Bytes::from_static(b"abcd")]);
    }

    #[tokio::test]
    async fn overflow_and_error_store_nothing() {
        let (c, f) = capture();
        let _ = TeeBody::new(stream(vec![Ok(Frame::data("abcdef".into()))]), 3, f)
            .collect()
            .await;
        assert!(c.lock().unwrap().iter().all(|b| b.is_empty()) || c.lock().unwrap().is_empty());
        let (c, f) = capture();
        let _ = TeeBody::new(
            stream(vec![Ok(Frame::data("a".into())), Err("boom".into())]),
            100,
            f,
        )
        .collect()
        .await;
        assert!(c.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn stores_under_real_hyper_server() {
        use hyper::service::service_fn;
        use hyper_util::rt::TokioIo;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (c, f) = capture();
        let f = Arc::new(Mutex::new(Some(f)));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let (s, _) = l.accept().await.unwrap();
            let svc = service_fn(move |_r: http::Request<hyper::body::Incoming>| {
                let f = f.clone();
                async move {
                    let on_done = f.lock().unwrap().take().unwrap();
                    Ok::<_, std::convert::Infallible>(http::Response::new(TeeBody::new(
                        full("hello world"),
                        100,
                        on_done,
                    )))
                }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(s), svc)
                .await;
        });
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out).await;
        assert!(String::from_utf8_lossy(&out).ends_with("hello world"));
        assert_eq!(*c.lock().unwrap(), vec![Bytes::from_static(b"hello world")]);
    }
}
