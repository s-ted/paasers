//! Socket creation and the accept loop.
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;

fn bind_raw(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let s = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    if addr.is_ipv6() {
        s.set_only_v6(false)?;
    }
    // On Windows SO_REUSEADDR lets another process steal the port, so it is Unix only.
    #[cfg(unix)]
    s.set_reuse_address(true)?;
    s.set_nonblocking(true)?;
    s.set_tcp_nodelay(true)?;
    s.bind(&addr.into())?;
    s.listen(1024)?;
    TcpListener::from_std(s.into())
}

/// `EAFNOSUPPORT`: Linux 97, Windows `WSAEAFNOSUPPORT` 10047.
fn af_unsupported(e: &std::io::Error) -> bool {
    matches!(e.raw_os_error(), Some(97 | 10047))
}

/// Binds a dual-stack listener, falling back to IPv4 when IPv6 is unavailable.
pub fn bind(addr: SocketAddr) -> std::io::Result<TcpListener> {
    match bind_raw(addr) {
        Err(e) if addr.is_ipv6() && addr.ip().is_unspecified() && af_unsupported(&e) => {
            let v4 = SocketAddr::from(([0, 0, 0, 0], addr.port()));
            tracing::warn!(%addr, fallback = %v4, "IPv6 unavailable, binding IPv4 only");
            bind_raw(v4)
        }
        r => r,
    }
}

/// Accepts connections until `shutdown` fires, enforcing the connection cap.
pub async fn accept_loop<F>(
    listener: TcpListener,
    conns: Arc<Semaphore>,
    shutdown: CancellationToken,
    on_conn: F,
) where
    F: Fn(TcpStream, SocketAddr, OwnedSemaphorePermit) + Send + 'static,
{
    loop {
        let accepted = tokio::select! {
            () = shutdown.cancelled() => break,
            r = listener.accept() => r,
        };
        let (tcp, peer) = match accepted {
            Ok(x) => x,
            Err(e) => {
                tracing::warn!(error = %e, "accept failed");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Ok(permit) = conns.clone().try_acquire_owned() else {
            tracing::debug!(%peer, "connection limit reached, dropping");
            continue;
        };
        let _ = tcp.set_nodelay(true);
        on_conn(tcp, peer, permit);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dual_stack_accepts_ipv4() {
        let l = bind("[::]:0".parse().unwrap()).unwrap();
        let port = l.local_addr().unwrap().port();
        let c = TcpStream::connect(("127.0.0.1", port));
        let (accepted, client) = tokio::join!(l.accept(), c);
        assert!(accepted.is_ok() && client.is_ok());
    }
}
