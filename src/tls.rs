//! TLS client support (rustls): handshake, negotiated-session info and the
//! certificate / protocol-version evaluation used by the check.

use std::io;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, ProtocolVersion, RootCertStore,
    SignatureScheme, StreamOwned,
};
use time::OffsetDateTime;

use crate::net::Stream;
use crate::nagios::Status;

/// TLS protocol versions accepted by `--minimum-tls-version`.
///
/// rustls only speaks 1.2 and 1.3; 1.0/1.1 are accepted for compatibility with
/// the upstream CLI (any session we can negotiate is trivially >= them).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
pub enum TlsVersion {
    #[value(name = "1.0")]
    V1_0,
    #[value(name = "1.1")]
    V1_1,
    #[value(name = "1.2")]
    V1_2,
    #[value(name = "1.3")]
    V1_3,
}

impl TlsVersion {
    pub fn short(self) -> &'static str {
        match self {
            TlsVersion::V1_0 => "1.0",
            TlsVersion::V1_1 => "1.1",
            TlsVersion::V1_2 => "1.2",
            TlsVersion::V1_3 => "1.3",
        }
    }
}

/// What we learned from a completed handshake.
pub struct TlsInfo {
    pub version: Option<TlsVersion>,
    pub cipher: String,
    pub certs: Vec<CertificateDer<'static>>,
}

impl TlsInfo {
    fn from_connection(conn: &ClientConnection) -> Self {
        let version = match conn.protocol_version() {
            Some(ProtocolVersion::TLSv1_2) => Some(TlsVersion::V1_2),
            Some(ProtocolVersion::TLSv1_3) => Some(TlsVersion::V1_3),
            _ => None,
        };
        Self {
            version,
            cipher: conn
                .negotiated_cipher_suite()
                .map(|s| format!("{:?}", s.suite()))
                .unwrap_or_else(|| "unknown cipher".into()),
            certs: conn.peer_certificates().map(<[_]>::to_vec).unwrap_or_default(),
        }
    }

    pub fn version_name(&self) -> String {
        match self.version {
            Some(v) => format!("TLS {}", v.short()),
            None => "unknown".into(),
        }
    }
}

/// Accepts any server certificate (like Go's `InsecureSkipVerify`), while still
/// checking handshake signatures so the session itself stays well-formed.
#[derive(Debug)]
struct NoVerify(Arc<CryptoProvider>);

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Reusable TLS client settings (config + SNI / verification name).
pub struct Connector {
    config: Arc<ClientConfig>,
    name: ServerName<'static>,
}

impl Connector {
    /// `verify == false` skips certificate validation (upstream default).
    pub fn new(verify: bool, server_name: &str) -> Result<Self, String> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(|e| format!("invalid TLS configuration: {e}"))?;

        let config = if verify {
            let mut roots = RootCertStore::empty();
            let loaded = rustls_native_certs::load_native_certs();
            for cert in loaded.certs {
                let _ = roots.add(cert);
            }
            if roots.is_empty() {
                return Err(format!(
                    "no system root certificates available for --verify ({} load error(s))",
                    loaded.errors.len()
                ));
            }
            builder.with_root_certificates(roots).with_no_client_auth()
        } else {
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
                .with_no_client_auth()
        };

        let name = ServerName::try_from(server_name.to_owned())
            .map_err(|e| format!("invalid TLS server name '{server_name}': {e}"))?;

        Ok(Self {
            config: Arc::new(config),
            name,
        })
    }

    /// Performs the client handshake over `stream` and returns the encrypted stream.
    pub fn handshake<S: Stream>(
        &self,
        mut stream: S,
    ) -> io::Result<(StreamOwned<ClientConnection, S>, TlsInfo)> {
        let mut conn = ClientConnection::new(self.config.clone(), self.name.clone())
            .map_err(io::Error::other)?;
        while conn.is_handshaking() {
            conn.complete_io(&mut stream)?;
        }
        let info = TlsInfo::from_connection(&conn);
        Ok((StreamOwned::new(conn, stream), info))
    }
}

impl<S: Stream> Stream for StreamOwned<ClientConnection, S> {
    fn close(&mut self) {
        self.conn.send_close_notify();
        while self.conn.wants_write() {
            if self.conn.write_tls(&mut self.sock).is_err() {
                break;
            }
        }
        self.sock.close();
    }
}

/// Status of a certificate expiring at `not_after`, using the upstream rule:
/// warn once within `warn_days` of expiry, critical once within `crit_days`
/// (0 days means "already expired").
pub fn cert_status(
    not_after: OffsetDateTime,
    now: OffsetDateTime,
    warn_days: u32,
    crit_days: u32,
) -> Status {
    let warn_at = not_after - time::Duration::days(warn_days.into());
    let crit_at = not_after - time::Duration::days(crit_days.into());
    if now > crit_at {
        Status::Critical
    } else if now > warn_at {
        Status::Warning
    } else {
        Status::Ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn cert_thresholds() {
        let not_after = datetime!(2030-01-31 00:00 UTC);
        let at = |d: OffsetDateTime| cert_status(not_after, d, 30, 7);
        assert_eq!(at(datetime!(2029-12-01 00:00 UTC)), Status::Ok);
        assert_eq!(at(datetime!(2030-01-05 00:00 UTC)), Status::Warning);
        assert_eq!(at(datetime!(2030-01-28 00:00 UTC)), Status::Critical);
        assert_eq!(at(datetime!(2030-02-02 00:00 UTC)), Status::Critical);
    }

    #[test]
    fn zero_thresholds_only_flag_expired() {
        let not_after = datetime!(2030-01-31 00:00 UTC);
        assert_eq!(cert_status(not_after, datetime!(2030-01-30 00:00 UTC), 0, 0), Status::Ok);
        assert_eq!(cert_status(not_after, datetime!(2030-02-01 00:00 UTC), 0, 0), Status::Critical);
    }

    #[test]
    fn versions_order() {
        assert!(TlsVersion::V1_3 > TlsVersion::V1_2);
        assert!(TlsVersion::V1_0 < TlsVersion::V1_1);
    }
}
