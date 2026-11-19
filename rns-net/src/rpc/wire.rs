//! The wire protocol: framing, authentication both ways, the server
//! session state machine and the payload codecs.

use super::*;

/// Largest message accepted from an RPC peer, as [`recv_bytes`] allows.
pub(super) const MAX_MESSAGE: usize = 64 * 1024 * 1024;

/// Largest message accepted before the request: challenges and their
/// answers are tens of bytes.
pub(super) const MAX_HANDSHAKE_MESSAGE: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SessionPhase {
    /// Waiting for the answer to our challenge.
    Auth,
    /// Waiting for the client's own challenge.
    ClientChallenge,
    /// Waiting for the client to accept our answer.
    ClientWelcome,
    Request,
    /// The request was handed out; waiting for [`ServerSession::answer`].
    Answering,
    Done,
}

/// The server side of one RPC connection, without the socket: the same
/// exchange as [`handle_connection`] (challenge both ways, one request, one
/// answer), fed bytes as they arrive and leaving bytes to send in a buffer.
/// The compact engine's driver serves its RPC connections with it.
pub(crate) struct ServerSession {
    auth_key: [u8; 32],
    /// Our challenge as sent, prefix included.
    challenge: Vec<u8>,
    phase: SessionPhase,
    input: Vec<u8>,
    output: Vec<u8>,
    sent: usize,
}

impl ServerSession {
    /// A session that opens by challenging the client with `random`.
    pub(crate) fn new(auth_key: [u8; 32], random: [u8; CHALLENGE_LEN]) -> Self {
        let mut challenge = Vec::with_capacity(CHALLENGE_PREFIX.len() + 8 + CHALLENGE_LEN);
        challenge.extend_from_slice(CHALLENGE_PREFIX);
        challenge.extend_from_slice(b"{sha256}");
        challenge.extend_from_slice(&random);
        let mut session = Self {
            auth_key,
            challenge,
            phase: SessionPhase::Auth,
            input: Vec::new(),
            output: Vec::new(),
            sent: 0,
        };
        let challenge = session.challenge.clone();
        session.queue(&challenge);
        session
    }

    pub(super) fn queue(&mut self, message: &[u8]) {
        self.output
            .extend_from_slice(&(message.len() as i32).to_be_bytes());
        self.output.extend_from_slice(message);
    }

    /// Take in `bytes` from the client. Returns the request once it is
    /// complete; an error ends the session, after [`Self::pending`] has
    /// been sent if the caller can.
    pub(crate) fn receive(&mut self, bytes: &[u8]) -> io::Result<Option<Vec<u8>>> {
        if !self.wants_input() {
            return Ok(None);
        }
        self.input.extend_from_slice(bytes);
        loop {
            let max = if self.phase == SessionPhase::Request {
                MAX_MESSAGE
            } else {
                MAX_HANDSHAKE_MESSAGE
            };
            let message = match take_message(&mut self.input, max) {
                Ok(Some(message)) => message,
                Ok(None) => return Ok(None),
                Err(error) => {
                    self.phase = SessionPhase::Done;
                    return Err(error);
                }
            };
            match self.phase {
                SessionPhase::Auth => {
                    let challenged = &self.challenge[CHALLENGE_PREFIX.len()..];
                    if verify_response(&self.auth_key, challenged, &message) {
                        self.queue(WELCOME);
                        self.phase = SessionPhase::ClientChallenge;
                    } else {
                        self.queue(FAILURE);
                        self.phase = SessionPhase::Done;
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "auth failed",
                        ));
                    }
                }
                SessionPhase::ClientChallenge => {
                    let Some(challenged) = message.strip_prefix(CHALLENGE_PREFIX) else {
                        self.phase = SessionPhase::Done;
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "expected challenge",
                        ));
                    };
                    let response = create_response(&self.auth_key, challenged);
                    self.queue(&response);
                    self.phase = SessionPhase::ClientWelcome;
                }
                SessionPhase::ClientWelcome => {
                    if message != WELCOME {
                        self.phase = SessionPhase::Done;
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "authentication failed",
                        ));
                    }
                    self.phase = SessionPhase::Request;
                }
                SessionPhase::Request => {
                    self.input = Vec::new();
                    self.phase = SessionPhase::Answering;
                    return Ok(Some(message));
                }
                SessionPhase::Answering | SessionPhase::Done => return Ok(None),
            }
        }
    }

    /// Queue the answer to the request [`Self::receive`] returned.
    pub(crate) fn answer(&mut self, response: &[u8]) {
        self.queue(response);
        self.phase = SessionPhase::Done;
    }

    /// End the session without an answer, as a failed request does.
    pub(crate) fn fail(&mut self) {
        self.phase = SessionPhase::Done;
    }

    /// Bytes waiting to be sent.
    pub(crate) fn pending(&self) -> &[u8] {
        &self.output[self.sent..]
    }

    /// `count` bytes of [`Self::pending`] were sent.
    pub(crate) fn sent(&mut self, count: usize) {
        self.sent += count;
        if self.sent >= self.output.len() {
            self.output.clear();
            self.sent = 0;
        }
    }

    /// Whether the session is waiting for bytes from the client.
    pub(crate) fn wants_input(&self) -> bool {
        !matches!(self.phase, SessionPhase::Answering | SessionPhase::Done)
    }

    /// Whether the session is over and everything it had to say was sent.
    pub(crate) fn finished(&self) -> bool {
        self.phase == SessionPhase::Done && self.pending().is_empty()
    }
}

/// Split one length-prefixed message off the front of `input`, as
/// [`recv_bytes`] reads one, once all of it has arrived.
pub(super) fn take_message(input: &mut Vec<u8>, max: usize) -> io::Result<Option<Vec<u8>>> {
    let Some(prefix) = input.first_chunk() else {
        return Ok(None);
    };
    let len = i32::from_be_bytes(*prefix);
    let (header, len) = if len < 0 {
        let Some(extended) = input.get(4..).and_then(<[u8]>::first_chunk) else {
            return Ok(None);
        };
        (12, u64::from_be_bytes(*extended))
    } else {
        (4, len as u64)
    };
    if len > max as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message too large",
        ));
    }
    let end = header + len as usize;
    if input.len() < end {
        return Ok(None);
    }
    let message = input[header..end].to_vec();
    input.drain(..end);
    Ok(Some(message))
}

/// A challenge's random part, from the OS.
pub(crate) fn challenge_random() -> [u8; CHALLENGE_LEN] {
    use rns_crypto::Rng;
    let mut random = [0u8; CHALLENGE_LEN];
    rns_crypto::OsRng.fill_bytes(&mut random);
    random
}

pub(super) fn decode_rpc_payload(data: &[u8]) -> io::Result<(PickleValue, RpcCodec)> {
    if let Ok(value) = msgpack::unpack_exact(data) {
        return Ok((msgpack_to_pickle(&value), RpcCodec::Msgpack));
    }
    pickle::decode(data)
        .map(|value| (value, RpcCodec::Pickle))
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}

pub(super) fn encode_rpc_payload(value: &PickleValue, codec: RpcCodec) -> Vec<u8> {
    match codec {
        RpcCodec::Msgpack => msgpack::pack(&pickle_to_msgpack(value)),
        RpcCodec::Pickle => pickle::encode(value),
    }
}

pub(super) fn pickle_to_msgpack(value: &PickleValue) -> MsgpackValue {
    match value {
        PickleValue::None => MsgpackValue::Nil,
        PickleValue::Bool(v) => MsgpackValue::Bool(*v),
        PickleValue::Int(v) if *v >= 0 => MsgpackValue::UInt(*v as u64),
        PickleValue::Int(v) => MsgpackValue::Int(*v),
        PickleValue::Float(v) => MsgpackValue::Float(*v),
        PickleValue::String(v) => MsgpackValue::Str(v.clone()),
        PickleValue::Bytes(v) => MsgpackValue::Bin(v.clone()),
        PickleValue::List(values) => {
            MsgpackValue::Array(values.iter().map(pickle_to_msgpack).collect())
        }
        PickleValue::Dict(values) => MsgpackValue::Map(
            values
                .iter()
                .map(|(key, value)| (pickle_to_msgpack(key), pickle_to_msgpack(value)))
                .collect(),
        ),
    }
}

pub(super) fn msgpack_to_pickle(value: &MsgpackValue) -> PickleValue {
    match value {
        MsgpackValue::Nil => PickleValue::None,
        MsgpackValue::Bool(v) => PickleValue::Bool(*v),
        MsgpackValue::UInt(v) if *v <= i64::MAX as u64 => PickleValue::Int(*v as i64),
        MsgpackValue::UInt(v) => PickleValue::Float(*v as f64),
        MsgpackValue::Int(v) => PickleValue::Int(*v),
        MsgpackValue::Float(v) => PickleValue::Float(*v),
        MsgpackValue::Bin(v) => PickleValue::Bytes(v.clone()),
        MsgpackValue::Str(v) => PickleValue::String(v.clone()),
        MsgpackValue::Array(values) => {
            PickleValue::List(values.iter().map(msgpack_to_pickle).collect())
        }
        MsgpackValue::Map(values) => PickleValue::Dict(
            values
                .iter()
                .map(|(key, value)| (msgpack_to_pickle(key), msgpack_to_pickle(value)))
                .collect(),
        ),
    }
}

/// Server-side authentication: challenge-response.
pub(super) fn server_auth<S: Read + Write>(stream: &mut S, auth_key: &[u8; 32]) -> io::Result<()> {
    // Generate challenge: #CHALLENGE#{sha256}<40 random bytes>
    let mut random_bytes = [0u8; CHALLENGE_LEN];
    // Use /dev/urandom for randomness
    {
        let mut f = std::fs::File::open("/dev/urandom")?;
        f.read_exact(&mut random_bytes)?;
    }

    let mut challenge_message = Vec::with_capacity(CHALLENGE_PREFIX.len() + 8 + CHALLENGE_LEN);
    challenge_message.extend_from_slice(CHALLENGE_PREFIX);
    challenge_message.extend_from_slice(b"{sha256}");
    challenge_message.extend_from_slice(&random_bytes);

    send_bytes(stream, &challenge_message)?;

    // Read response (max 256 bytes)
    let response = recv_bytes(stream)?;

    // Verify response
    // The message to HMAC is everything after #CHALLENGE# (i.e. {sha256}<random>)
    let message = &challenge_message[CHALLENGE_PREFIX.len()..];

    if verify_response(auth_key, message, &response) {
        send_bytes(stream, WELCOME)?;
        Ok(())
    } else {
        send_bytes(stream, FAILURE)?;
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "auth failed",
        ))
    }
}

/// Verify a client's HMAC response.
pub(super) fn verify_response(auth_key: &[u8; 32], message: &[u8], response: &[u8]) -> bool {
    // Modern protocol: response = {sha256}<hmac-sha256 digest>
    if response.starts_with(b"{sha256}") {
        let digest = &response[8..];
        let expected = hmac_sha256(auth_key, message);
        constant_time_eq(digest, &expected)
    }
    // Legacy protocol: response = raw 16-byte HMAC-MD5 digest
    else if response.len() == 16 {
        let expected = hmac_md5(auth_key, message);
        constant_time_eq(response, &expected)
    }
    // Legacy with {md5} prefix
    else if response.starts_with(b"{md5}") {
        let digest = &response[5..];
        let expected = hmac_md5(auth_key, message);
        constant_time_eq(digest, &expected)
    } else {
        false
    }
}

/// Constant-time byte comparison.
pub(super) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Send bytes with 4-byte big-endian length prefix.
pub(super) fn send_bytes<S: Write>(stream: &mut S, data: &[u8]) -> io::Result<()> {
    let len = data.len() as i32;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(data)?;
    stream.flush()
}

/// Receive bytes with 4-byte big-endian length prefix.
pub(super) fn recv_bytes<S: Read>(stream: &mut S) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = i32::from_be_bytes(len_buf);

    if len < 0 {
        // Extended format: 8-byte length
        let mut len8_buf = [0u8; 8];
        stream.read_exact(&mut len8_buf)?;
        let len = u64::from_be_bytes(len8_buf) as usize;
        if len > 64 * 1024 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "message too large",
            ));
        }
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf)?;
        Ok(buf)
    } else {
        let len = len as usize;
        if len > 64 * 1024 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "message too large",
            ));
        }
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf)?;
        Ok(buf)
    }
}

/// Client-side authentication: answer the server's challenge.
pub(super) fn client_auth<S: Read + Write>(stream: &mut S, auth_key: &[u8; 32]) -> io::Result<()> {
    answer_challenge(stream, auth_key)?;
    server_auth(stream, auth_key)
}

pub(super) fn answer_challenge<S: Read + Write>(
    stream: &mut S,
    auth_key: &[u8; 32],
) -> io::Result<()> {
    // Read challenge
    let challenge = recv_bytes(stream)?;

    if !challenge.starts_with(CHALLENGE_PREFIX) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected challenge",
        ));
    }

    let message = &challenge[CHALLENGE_PREFIX.len()..];

    // Create HMAC response
    let response = create_response(auth_key, message);
    send_bytes(stream, &response)?;

    // Read welcome/failure
    let result = recv_bytes(stream)?;
    if result == WELCOME {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "authentication failed",
        ))
    }
}

/// Create an HMAC response to a challenge message.
pub(super) fn create_response(auth_key: &[u8; 32], message: &[u8]) -> Vec<u8> {
    // Check if message has {sha256} prefix (modern protocol)
    if message.starts_with(b"{sha256}") || message.len() > 20 {
        // Modern protocol: use HMAC-SHA256 with {sha256} prefix
        let digest = hmac_sha256(auth_key, message);
        let mut response = Vec::with_capacity(8 + 32);
        response.extend_from_slice(b"{sha256}");
        response.extend_from_slice(&digest);
        response
    } else {
        // Legacy protocol: raw HMAC-MD5
        let digest = hmac_md5(auth_key, message);
        digest.to_vec()
    }
}

/// Derive the RPC auth key from transport identity private key.
pub fn derive_auth_key(private_key: &[u8]) -> [u8; 32] {
    sha256(private_key)
}
