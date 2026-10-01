//! TLS handshake for accepted TCP connections.
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, server::TlsStream};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

pub fn acceptor(cfg: rustls::ServerConfig) -> TlsAcceptor {
    TlsAcceptor::from(Arc::new(cfg))
}

/// Performs the handshake under a timeout. Failures are only logged at debug level.
pub async fn handshake(acceptor: &TlsAcceptor, tcp: TcpStream) -> Option<TlsStream<TcpStream>> {
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
        Ok(Ok(s)) => Some(s),
        Ok(Err(e)) => {
            tracing::debug!(error = %e, "tls handshake failed");
            None
        }
        Err(_) => {
            tracing::debug!("tls handshake timed out");
            None
        }
    }
}
