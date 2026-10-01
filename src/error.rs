//! Data plane errors and their HTTP status mapping.
use http::StatusCode;

#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    #[error("bad request: {0}")]
    BadRequest(&'static str),
    #[error("not found")]
    UnknownHost,
    #[error("payload too large")]
    PayloadTooLarge,
    #[error("loop detected")]
    Loop,
    #[error("no healthy upstream")]
    NoHealthyUpstream,
    #[error("upstream connect: {0}")]
    UpstreamConnect(String),
    #[error("upstream timeout")]
    UpstreamTimeout,
    #[error("upstream: {0}")]
    Upstream(String),
}

impl GatewayError {
    pub fn status(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::UnknownHost => StatusCode::NOT_FOUND,
            Self::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::Loop => StatusCode::LOOP_DETECTED,
            Self::NoHealthyUpstream => StatusCode::SERVICE_UNAVAILABLE,
            Self::UpstreamConnect(_) | Self::Upstream(_) => StatusCode::BAD_GATEWAY,
            Self::UpstreamTimeout => StatusCode::GATEWAY_TIMEOUT,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_mapping() {
        assert_eq!(GatewayError::Loop.status().as_u16(), 508);
        assert_eq!(GatewayError::UpstreamTimeout.status().as_u16(), 504);
        assert_eq!(GatewayError::UnknownHost.status().as_u16(), 404);
    }
}
