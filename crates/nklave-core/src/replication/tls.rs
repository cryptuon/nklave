//! TLS configuration for replication protocol
//!
//! Provides mTLS (mutual TLS) support for primary-passive communication.

use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
    ClientConfig, RootCertStore, ServerConfig,
};
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};
use tracing::{debug, info};

/// TLS configuration for replication
#[derive(Debug, Clone)]
pub struct ReplicationTlsConfig {
    /// Path to the certificate file (PEM format)
    pub cert_path: PathBuf,

    /// Path to the private key file (PEM format)
    pub key_path: PathBuf,

    /// Path to the CA certificate for verifying peers (PEM format)
    pub ca_cert_path: PathBuf,

    /// Whether to require client certificates (mTLS)
    pub require_client_cert: bool,
}

/// Errors from TLS operations
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("Failed to read certificate file: {0}")]
    CertificateRead(String),

    #[error("Failed to read private key file: {0}")]
    PrivateKeyRead(String),

    #[error("Failed to read CA certificate file: {0}")]
    CaCertificateRead(String),

    #[error("No certificates found in file")]
    NoCertificates,

    #[error("No private key found in file")]
    NoPrivateKey,

    #[error("TLS configuration error: {0}")]
    Configuration(String),

    #[error("TLS handshake failed: {0}")]
    Handshake(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

impl ReplicationTlsConfig {
    /// Create a new TLS configuration
    pub fn new(cert_path: PathBuf, key_path: PathBuf, ca_cert_path: PathBuf) -> Self {
        Self {
            cert_path,
            key_path,
            ca_cert_path,
            require_client_cert: true, // Default to mTLS
        }
    }

    /// Load certificates from the certificate file
    fn load_certs(&self) -> Result<Vec<CertificateDer<'static>>, TlsError> {
        let file = File::open(&self.cert_path).map_err(|e| {
            TlsError::CertificateRead(format!("{}: {}", self.cert_path.display(), e))
        })?;
        let mut reader = BufReader::new(file);

        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
            .filter_map(|r| r.ok())
            .collect();

        if certs.is_empty() {
            return Err(TlsError::NoCertificates);
        }

        debug!(count = certs.len(), path = %self.cert_path.display(), "Loaded certificates");
        Ok(certs)
    }

    /// Load the private key from the key file
    fn load_private_key(&self) -> Result<PrivateKeyDer<'static>, TlsError> {
        let file = File::open(&self.key_path).map_err(|e| {
            TlsError::PrivateKeyRead(format!("{}: {}", self.key_path.display(), e))
        })?;
        let mut reader = BufReader::new(file);

        let key = rustls_pemfile::private_key(&mut reader)
            .map_err(|e| TlsError::PrivateKeyRead(e.to_string()))?
            .ok_or(TlsError::NoPrivateKey)?;

        debug!(path = %self.key_path.display(), "Loaded private key");
        Ok(key)
    }

    /// Load CA certificates for peer verification
    fn load_ca_certs(&self) -> Result<RootCertStore, TlsError> {
        let file = File::open(&self.ca_cert_path).map_err(|e| {
            TlsError::CaCertificateRead(format!("{}: {}", self.ca_cert_path.display(), e))
        })?;
        let mut reader = BufReader::new(file);

        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
            .filter_map(|r| r.ok())
            .collect();

        if certs.is_empty() {
            return Err(TlsError::NoCertificates);
        }

        let mut root_store = RootCertStore::empty();
        for cert in certs {
            root_store.add(cert).map_err(|e| {
                TlsError::Configuration(format!("Failed to add CA certificate: {}", e))
            })?;
        }

        debug!(path = %self.ca_cert_path.display(), "Loaded CA certificates");
        Ok(root_store)
    }

    /// Build a TLS acceptor for the primary node (server)
    pub fn build_acceptor(&self) -> Result<TlsAcceptor, TlsError> {
        let certs = self.load_certs()?;
        let key = self.load_private_key()?;
        let ca_certs = self.load_ca_certs()?;

        let mut config = if self.require_client_cert {
            // mTLS: require and verify client certificates
            let client_cert_verifier = tokio_rustls::rustls::server::WebPkiClientVerifier::builder(
                Arc::new(ca_certs),
            )
            .build()
            .map_err(|e| TlsError::Configuration(format!("Failed to build client verifier: {}", e)))?;

            ServerConfig::builder()
                .with_client_cert_verifier(client_cert_verifier)
                .with_single_cert(certs, key)
                .map_err(|e| TlsError::Configuration(e.to_string()))?
        } else {
            // Server-only TLS, no client cert required
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .map_err(|e| TlsError::Configuration(e.to_string()))?
        };

        // Disable TLS 1.2 to only allow TLS 1.3
        config.alpn_protocols = vec![b"nklave-repl".to_vec()];

        info!(
            require_client_cert = self.require_client_cert,
            "TLS acceptor configured for primary"
        );

        Ok(TlsAcceptor::from(Arc::new(config)))
    }

    /// Build a TLS connector for the passive node (client)
    pub fn build_connector(&self) -> Result<TlsConnector, TlsError> {
        let certs = self.load_certs()?;
        let key = self.load_private_key()?;
        let ca_certs = self.load_ca_certs()?;

        let mut config = ClientConfig::builder()
            .with_root_certificates(ca_certs)
            .with_client_auth_cert(certs, key)
            .map_err(|e| TlsError::Configuration(e.to_string()))?;

        config.alpn_protocols = vec![b"nklave-repl".to_vec()];

        info!("TLS connector configured for passive");

        Ok(TlsConnector::from(Arc::new(config)))
    }
}

/// Wrapper for TLS stream that works with both client and server connections
pub enum ReplicationTlsStream {
    /// Server-side TLS stream (primary accepting passive connections)
    Server(TlsStream<TcpStream>),
    /// Client-side TLS stream (passive connecting to primary)
    Client(TlsStream<TcpStream>),
    /// Plain TCP stream (when TLS is disabled)
    Plain(TcpStream),
}

impl ReplicationTlsStream {
    /// Accept a TLS connection on the server side
    pub async fn accept(
        acceptor: &TlsAcceptor,
        stream: TcpStream,
    ) -> Result<Self, TlsError> {
        let tls_stream = acceptor.accept(stream).await.map_err(|e| {
            TlsError::Handshake(format!("Server TLS handshake failed: {}", e))
        })?;
        Ok(ReplicationTlsStream::Server(TlsStream::Server(tls_stream)))
    }

    /// Connect with TLS on the client side
    pub async fn connect(
        connector: &TlsConnector,
        server_name: &str,
        stream: TcpStream,
    ) -> Result<Self, TlsError> {
        let server_name = ServerName::try_from(server_name.to_string())
            .map_err(|e| TlsError::Configuration(format!("Invalid server name: {}", e)))?;

        let tls_stream = connector.connect(server_name, stream).await.map_err(|e| {
            TlsError::Handshake(format!("Client TLS handshake failed: {}", e))
        })?;
        Ok(ReplicationTlsStream::Client(TlsStream::Client(tls_stream)))
    }

    /// Wrap a plain TCP stream (when TLS is disabled)
    pub fn plain(stream: TcpStream) -> Self {
        ReplicationTlsStream::Plain(stream)
    }
}

// Implement AsyncRead and AsyncWrite for ReplicationTlsStream
impl tokio::io::AsyncRead for ReplicationTlsStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            ReplicationTlsStream::Server(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            ReplicationTlsStream::Client(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            ReplicationTlsStream::Plain(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for ReplicationTlsStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        match self.get_mut() {
            ReplicationTlsStream::Server(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            ReplicationTlsStream::Client(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            ReplicationTlsStream::Plain(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            ReplicationTlsStream::Server(s) => std::pin::Pin::new(s).poll_flush(cx),
            ReplicationTlsStream::Client(s) => std::pin::Pin::new(s).poll_flush(cx),
            ReplicationTlsStream::Plain(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            ReplicationTlsStream::Server(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            ReplicationTlsStream::Client(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            ReplicationTlsStream::Plain(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_tls_config_creation() {
        let config = ReplicationTlsConfig::new(
            PathBuf::from("/path/to/cert.pem"),
            PathBuf::from("/path/to/key.pem"),
            PathBuf::from("/path/to/ca.pem"),
        );

        assert!(config.require_client_cert);
        assert_eq!(config.cert_path, PathBuf::from("/path/to/cert.pem"));
    }

    #[test]
    fn test_tls_config_without_client_cert() {
        let mut config = ReplicationTlsConfig::new(
            PathBuf::from("/path/to/cert.pem"),
            PathBuf::from("/path/to/key.pem"),
            PathBuf::from("/path/to/ca.pem"),
        );
        config.require_client_cert = false;

        assert!(!config.require_client_cert);
    }
}
