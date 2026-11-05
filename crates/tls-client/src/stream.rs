//! Bounded, transport-independent TLS records for native stream adapters.
//! This layer cannot open sockets or change certificate trust. A caller must
//! transport ciphertext over an already-authorized connection.
use crate::{
    MAX_TLS_HANDSHAKE_BUFFER, MAX_TLS_PLAINTEXT, MAX_TLS_RECORD, TlsConnection, TlsError, TlsEvent,
    TlsState,
};
use alloc::{sync::Arc, vec::Vec};
use rustls::ClientConfig;
use zeroize::Zeroize;

/// Queue budget per direction, independent of network input sizes.
pub const QUEUE_LIMIT: usize = MAX_TLS_HANDSHAKE_BUFFER;

/// A verified client engine plus bounded plaintext and ciphertext queues.
pub struct Stream {
    connection: TlsConnection,
    receive: Vec<u8>,
    transmit: Vec<u8>,
    failure: Option<TlsError>,
}

impl Drop for Stream {
    fn drop(&mut self) {
        self.receive.zeroize();
    }
}

impl Stream {
    /// Create a client using the supplied verifier/configuration. Produces the
    /// initial ClientHello in `ciphertext()` without performing transport I/O.
    pub fn new(config: Arc<ClientConfig>, hostname: &str) -> Result<Self, TlsError> {
        let mut stream = Self {
            connection: TlsConnection::new(config, hostname)?,
            receive: Vec::new(),
            transmit: Vec::new(),
            failure: None,
        };
        stream.advance()?;
        Ok(stream)
    }

    /// Process available records. Any failure is sticky; rejected data cannot
    /// subsequently be read or transmitted as if verification had succeeded.
    pub fn advance(&mut self) -> Result<(), TlsError> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        let result = self.process();
        if let Err(error) = result {
            self.failure = Some(error);
            self.receive.zeroize();
            self.transmit.clear();
        }
        result
    }

    fn process(&mut self) -> Result<(), TlsError> {
        // The core consumes bytes or changes protocol state on every event.
        // Bound work even if a future engine version violates that contract.
        for _ in 0..128 {
            match self.connection.next_event()? {
                TlsEvent::Transmit(bytes) => append(&mut self.transmit, &bytes)?,
                TlsEvent::Plaintext(mut bytes) => {
                    let result = append(&mut self.receive, &bytes);
                    bytes.zeroize();
                    result?;
                }
                TlsEvent::Established => {}
                TlsEvent::NeedReceive | TlsEvent::PeerClosed | TlsEvent::Closed => return Ok(()),
            }
        }
        Err(TlsError::BufferLimit)
    }

    /// Feed one bounded ciphertext fragment and process it. The caller retains
    /// responsibility for backpressure and must drain plaintext as it reads.
    pub fn receive_tls(&mut self, bytes: &[u8]) -> Result<(), TlsError> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if let Err(error) = self.connection.receive_tls(bytes) {
            self.failure = Some(error);
            self.receive.zeroize();
            self.transmit.clear();
            return Err(error);
        }
        self.advance()
    }

    /// Encrypt a single application record. Returns BufferLimit before
    /// consuming a nonce if the ciphertext queue lacks room for a full record.
    pub fn write(&mut self, bytes: &[u8]) -> Result<(), TlsError> {
        self.advance()?;
        if bytes.len() > MAX_TLS_PLAINTEXT || self.transmit.len() > QUEUE_LIMIT - MAX_TLS_RECORD {
            return Err(TlsError::BufferLimit);
        }
        if bytes.is_empty() {
            return Ok(());
        }
        let encrypted = self.connection.encrypt(bytes)?;
        append(&mut self.transmit, &encrypted)
    }

    /// Queue an authenticated close notification. Transport must flush the
    /// ciphertext before closing the underlying stream.
    pub fn close_notify(&mut self) -> Result<(), TlsError> {
        self.advance()?;
        if self.transmit.len() > QUEUE_LIMIT - MAX_TLS_RECORD {
            return Err(TlsError::BufferLimit);
        }
        let bytes = self.connection.close_notify()?;
        append(&mut self.transmit, &bytes)
    }

    /// Inspect pending ciphertext without consuming it; partial writes are safe.
    pub fn ciphertext(&self) -> &[u8] {
        if self.state() == TlsState::Failed {
            &[]
        } else {
            &self.transmit
        }
    }
    /// Acknowledge only bytes successfully transported.
    pub fn consume_ciphertext(&mut self, count: usize) -> Result<(), TlsError> {
        if count > self.transmit.len() {
            return Err(TlsError::InvalidState);
        }
        self.transmit.drain(..count);
        Ok(())
    }
    /// Inspect authenticated plaintext. Failed verification yields no bytes.
    pub fn plaintext(&self) -> &[u8] {
        if self.state() == TlsState::Failed {
            &[]
        } else {
            &self.receive
        }
    }
    /// Acknowledge plaintext only after a successful caller-buffer copy.
    pub fn consume_plaintext(&mut self, count: usize) -> Result<(), TlsError> {
        if count > self.plaintext().len() {
            return Err(TlsError::InvalidState);
        }
        let remaining = self.receive.len() - count;
        self.receive.copy_within(count.., 0);
        self.receive[remaining..].zeroize();
        self.receive.truncate(remaining);
        Ok(())
    }
    /// Current protocol state; a sticky record or verification error wins.
    pub fn state(&self) -> TlsState {
        if self.failure.is_some() {
            TlsState::Failed
        } else {
            self.connection.state()
        }
    }
    /// Read-only verified connection metadata; cannot alter its trust policy.
    pub fn connection(&self) -> &TlsConnection {
        &self.connection
    }
}

fn append(queue: &mut Vec<u8>, bytes: &[u8]) -> Result<(), TlsError> {
    if bytes.len() > QUEUE_LIMIT.saturating_sub(queue.len()) {
        return Err(TlsError::BufferLimit);
    }
    queue.extend_from_slice(bytes);
    Ok(())
}
