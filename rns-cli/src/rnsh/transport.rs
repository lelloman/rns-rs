//! Link events and sends, as the listener and initiator see them.

use super::*;

#[derive(Debug)]
pub(super) enum RnshEvent {
    Announce(rns_net::AnnouncedIdentity),
    LinkEstablished {
        link_id: [u8; 16],
        is_initiator: bool,
    },
    LinkClosed([u8; 16]),
    RemoteIdentified {
        link_id: [u8; 16],
        identity_hash: IdentityHash,
    },
    ChannelMessage {
        link_id: [u8; 16],
        msgtype: u16,
        payload: Vec<u8>,
    },
    ProcessOutput {
        link_id: [u8; 16],
        stream_id: u16,
        data: Vec<u8>,
        budget: Arc<OutputBudget>,
    },
    ProcessExited {
        link_id: [u8; 16],
        code: i32,
    },
    LocalStdin(Vec<u8>),
    LocalStdinEof,
}

pub(super) struct RnshCallbacks {
    pub(super) tx: mpsc::Sender<RnshEvent>,
}

impl Callbacks for RnshCallbacks {
    fn on_announce(&mut self, announced: rns_net::AnnouncedIdentity) {
        let _ = self.tx.send(RnshEvent::Announce(announced));
    }

    fn on_link_established(
        &mut self,
        link_id: rns_net::LinkId,
        _dest_hash: DestHash,
        _rtt: f64,
        is_initiator: bool,
    ) {
        let _ = self.tx.send(RnshEvent::LinkEstablished {
            link_id: link_id.0,
            is_initiator,
        });
    }

    fn on_link_closed(
        &mut self,
        link_id: rns_net::LinkId,
        _reason: Option<rns_net::TeardownReason>,
    ) {
        let _ = self.tx.send(RnshEvent::LinkClosed(link_id.0));
    }

    fn on_remote_identified(
        &mut self,
        link_id: rns_net::LinkId,
        identity_hash: IdentityHash,
        _public_key: [u8; 64],
    ) {
        let _ = self.tx.send(RnshEvent::RemoteIdentified {
            link_id: link_id.0,
            identity_hash,
        });
    }

    fn on_channel_message(&mut self, link_id: rns_net::LinkId, msgtype: u16, payload: Vec<u8>) {
        let _ = self.tx.send(RnshEvent::ChannelMessage {
            link_id: link_id.0,
            msgtype,
            payload,
        });
    }
}

pub(super) trait RnshTransport {
    fn send_rnsh_message(&self, link_id: [u8; 16], message: &RnshMessage) -> Result<(), RnshError>;

    fn teardown_rnsh_link(&self, link_id: [u8; 16]) -> Result<(), RnshError>;
}

impl RnshTransport for RnsNode {
    fn send_rnsh_message(&self, link_id: [u8; 16], message: &RnshMessage) -> Result<(), RnshError> {
        self.try_send_channel_message(link_id, message.msgtype(), message.pack())?;
        Ok(())
    }

    fn teardown_rnsh_link(&self, link_id: [u8; 16]) -> Result<(), RnshError> {
        self.teardown_link(link_id)?;
        Ok(())
    }
}
