//! Links: requests, resources, channels and direct paths.

use super::*;

impl RnsNode {
    /// Create an outbound link to a destination.
    ///
    /// Returns the link_id on success.
    pub fn create_link(
        &self,
        dest_hash: [u8; 16],
        dest_sig_pub_bytes: [u8; 32],
    ) -> Result<[u8; 16], SendError> {
        self.reject_new_work_if_draining()?;
        let (response_tx, response_rx) = std::sync::mpsc::channel();
        self.tx
            .send(Event::CreateLink {
                dest_hash,
                dest_sig_pub_bytes,
                response_tx,
            })
            .map_err(|_| SendError)?;
        let link_id = response_rx.recv().map_err(|_| SendError)?;
        if link_id == [0u8; 16] {
            Err(SendError)
        } else {
            Ok(link_id)
        }
    }

    /// Send a request on an established link.
    pub fn send_request(
        &self,
        link_id: [u8; 16],
        path: &str,
        data: &[u8],
    ) -> Result<(), SendError> {
        self.send_request_with_max_response_size(link_id, path, data, None)
    }

    /// Send a request with an optional maximum accepted response size.
    pub fn send_request_with_max_response_size(
        &self,
        link_id: [u8; 16],
        path: &str,
        data: &[u8],
        max_response_size: Option<usize>,
    ) -> Result<(), SendError> {
        self.send_request_with_options(link_id, path, data, max_response_size, None)
    }

    /// Send a request that fails (`on_request_failed` with
    /// `RequestFailure::TimedOut`) when no response arrives within
    /// `timeout` seconds, upstream's `Link.request(timeout=...)`.
    pub fn send_request_with_options(
        &self,
        link_id: [u8; 16],
        path: &str,
        data: &[u8],
        max_response_size: Option<usize>,
        timeout: Option<f64>,
    ) -> Result<(), SendError> {
        self.reject_new_work_if_draining()?;
        self.tx
            .send(Event::SendRequest {
                link_id,
                path: path.to_string(),
                data: data.to_vec(),
                max_response_size,
                timeout,
            })
            .map_err(|_| SendError)
    }

    /// Identify on a link (reveal identity to remote peer).
    pub fn identify_on_link(
        &self,
        link_id: [u8; 16],
        identity_prv_key: [u8; 64],
    ) -> Result<(), SendError> {
        self.reject_new_work_if_draining()?;
        self.tx
            .send(Event::IdentifyOnLink {
                link_id,
                identity_prv_key,
            })
            .map_err(|_| SendError)
    }

    /// Tear down a link.
    pub fn teardown_link(&self, link_id: [u8; 16]) -> Result<(), SendError> {
        self.tx
            .send(Event::TeardownLink { link_id })
            .map_err(|_| SendError)
    }

    /// Send a resource on an established link.
    pub fn send_resource(
        &self,
        link_id: [u8; 16],
        data: Vec<u8>,
        metadata: Option<Vec<u8>>,
    ) -> Result<(), SendError> {
        self.send_resource_with_auto_compress(link_id, data, metadata, true)
    }

    /// Send a resource on an established link, controlling automatic compression.
    ///
    /// Set `auto_compress` to `false` when the application knows its payload is
    /// already compressed or encrypted. This skips the compression attempt;
    /// link encryption and Resource integrity checks still apply. With `true`,
    /// eligible payloads are fully compressed and the result is used only when
    /// smaller. Even a rejected attempt costs CPU, while disabling compression
    /// for compressible content can substantially increase transmitted bytes.
    ///
    /// Buffered sends of at least 16 KiB that fit one Resource segment can
    /// prepare compression on a node-owned worker. Its admission budget is eight
    /// jobs and 8 MiB of owned input capacity plus reserved compressed output.
    /// Codec workspace and the running job's temporary input are additional.
    /// Saturation, small/split Resources and worker startup failure use synchronous
    /// preparation, preserving earlier buffered sends on the same link. This
    /// improves responsiveness for eligible sends; it does not provide a latency
    /// bound under overload. Reader transfers and request responses keep their
    /// existing synchronous preparation paths.
    pub fn send_resource_with_auto_compress(
        &self,
        link_id: [u8; 16],
        data: Vec<u8>,
        metadata: Option<Vec<u8>>,
        auto_compress: bool,
    ) -> Result<(), SendError> {
        self.send_resource_with_options(
            link_id,
            data,
            metadata,
            crate::resource::ResourceSendOptions {
                auto_compress,
                ..Default::default()
            },
        )
    }

    /// Send a resource on an established link with explicit send options,
    /// including the application flag the receiver sees with the data.
    pub fn send_resource_with_options(
        &self,
        link_id: [u8; 16],
        data: Vec<u8>,
        metadata: Option<Vec<u8>>,
        options: crate::resource::ResourceSendOptions,
    ) -> Result<(), SendError> {
        self.reject_new_work_if_draining()?;
        self.tx
            .send(Event::SendResource {
                link_id,
                data,
                metadata,
                options,
            })
            .map_err(|_| SendError)
    }

    /// Send a Resource from a sequential reader without retaining the full
    /// logical payload in memory.
    pub fn send_resource_reader<R: Read + Send + 'static>(
        &self,
        link_id: [u8; 16],
        reader: R,
        declared_length: u64,
        metadata: Option<Vec<u8>>,
        auto_compress: bool,
    ) -> Result<crate::resource::ResourceTransferId, SendError> {
        self.send_resource_reader_with_options(
            link_id,
            reader,
            declared_length,
            metadata,
            crate::resource::ResourceSendOptions {
                auto_compress,
                ..Default::default()
            },
        )
    }

    /// Send a Resource from a sequential reader with explicit send options.
    pub fn send_resource_reader_with_options<R: Read + Send + 'static>(
        &self,
        link_id: [u8; 16],
        reader: R,
        declared_length: u64,
        metadata: Option<Vec<u8>>,
        options: crate::resource::ResourceSendOptions,
    ) -> Result<crate::resource::ResourceTransferId, SendError> {
        self.reject_new_work_if_draining()?;
        let transfer_id = crate::resource::ResourceTransferId(
            NEXT_RESOURCE_TRANSFER_ID.fetch_add(1, Ordering::Relaxed),
        );
        self.tx
            .send(Event::SendResourceStream {
                link_id,
                transfer_id,
                reader: Box::new(reader),
                declared_length,
                metadata,
                options,
            })
            .map_err(|_| SendError)?;
        Ok(transfer_id)
    }

    /// Send a file as a bounded-memory streaming Resource.
    pub fn send_resource_file(
        &self,
        link_id: [u8; 16],
        path: impl AsRef<Path>,
        metadata: Option<Vec<u8>>,
        auto_compress: bool,
    ) -> io::Result<crate::resource::ResourceTransferId> {
        let file = std::fs::File::open(path.as_ref())?;
        let length = file.metadata()?.len();
        self.send_resource_reader(link_id, file, length, metadata, auto_compress)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "RNS driver shut down"))
    }

    /// Select delivery policy for independent incoming Resources on a link.
    pub fn set_resource_receive_mode(
        &self,
        link_id: [u8; 16],
        mode: crate::resource::ResourceReceiveMode,
    ) -> Result<(), SendError> {
        self.tx
            .send(Event::SetResourceReceiveMode { link_id, mode })
            .map_err(|_| SendError)
    }

    /// Set the resource acceptance strategy for a link.
    ///
    /// 0 = AcceptNone, 1 = AcceptAll, 2 = AcceptApp
    pub fn set_resource_strategy(&self, link_id: [u8; 16], strategy: u8) -> Result<(), SendError> {
        self.tx
            .send(Event::SetResourceStrategy { link_id, strategy })
            .map_err(|_| SendError)
    }

    /// Accept or reject a pending resource (for AcceptApp strategy).
    pub fn accept_resource(
        &self,
        link_id: [u8; 16],
        resource_hash: Vec<u8>,
        accept: bool,
    ) -> Result<(), SendError> {
        if accept {
            self.reject_new_work_if_draining()?;
        }
        self.tx
            .send(Event::AcceptResource {
                link_id,
                resource_hash,
                accept,
            })
            .map_err(|_| SendError)
    }

    /// Send a channel message on a link (compatibility API).
    pub fn send_channel_message(
        &self,
        link_id: [u8; 16],
        msgtype: u16,
        payload: Vec<u8>,
    ) -> Result<(), SendError> {
        self.try_send_channel_message(link_id, msgtype, payload)
            .map_err(|_| SendError)
    }

    /// Attempt to enqueue a channel message, preserving temporary backpressure.
    /// A NotReady result means no sequence was reserved; callers can retry the
    /// same payload when capacity is available. Other failures are terminal.
    pub fn try_send_channel_message(
        &self,
        link_id: [u8; 16],
        msgtype: u16,
        payload: Vec<u8>,
    ) -> Result<(), ChannelSendError> {
        self.reject_new_work_if_draining()
            .map_err(|_| ChannelSendError::Unavailable)?;
        let (response_tx, response_rx) = std::sync::mpsc::channel();
        self.tx
            .send(Event::SendChannelMessage {
                link_id,
                msgtype,
                payload,
                response_tx,
            })
            .map_err(|_| ChannelSendError::Unavailable)?;
        response_rx
            .recv()
            .map_err(|_| ChannelSendError::Unavailable)?
            .map_err(ChannelSendError::from)
    }

    /// Propose a direct P2P connection to a peer via NAT hole punching.
    ///
    /// The link must be active and connected through a backbone node.
    /// If successful, a direct UDP connection will be established, bypassing the backbone.
    pub fn propose_direct_connect(&self, link_id: [u8; 16]) -> Result<(), SendError> {
        self.reject_new_work_if_draining()?;
        self.tx
            .send(Event::ProposeDirectConnect { link_id })
            .map_err(|_| SendError)
    }

    /// Make the link's direct path silently drop all traffic in both
    /// directions on this side, as a network that stopped carrying it
    /// would. For tests of the fallback to the original route.
    #[doc(hidden)]
    pub fn blackhole_direct_path_for_testing(&self, link_id: [u8; 16]) -> Result<(), SendError> {
        self.tx
            .send(Event::BlackholeDirectPath { link_id })
            .map_err(|_| SendError)
    }

    /// Set the policy for handling incoming direct-connect proposals.
    pub fn set_direct_connect_policy(
        &self,
        policy: crate::holepunch::orchestrator::HolePunchPolicy,
    ) -> Result<(), SendError> {
        self.tx
            .send(Event::SetDirectConnectPolicy { policy })
            .map_err(|_| SendError)
    }

    /// Wait for capacity and transmit a Link packet through its interface writer.
    ///
    /// Success means the underlying transport accepted the complete packet,
    /// not that the peer received or acknowledged it. Cancellation before
    /// admission sends nothing; after admission, dropping this future does not
    /// cancel transmission. This future is independent of any async runtime.
    /// The driver's configured event capacity also bounds the total number of
    /// admitted confirmed sends (Links, packets and announcements), including
    /// frames waiting for an interface or write.
    /// A transmission error can follow a partial write; only QueueFull from the
    /// try API guarantees that retrying cannot duplicate an admitted packet.
    pub async fn send_on_link(
        &self,
        link_id: [u8; 16],
        data: Vec<u8>,
        context: u8,
    ) -> Result<(), crate::link_send::LinkSendError> {
        use crate::link_send::Completion;
        let tracking = self.tx.link_send_pool().track(link_id, true);
        let permit = self.tx.link_send_pool().acquire().await?;
        let (completion, receipt) = Completion::new_tracked(permit, tracking);
        self.tx
            .send_async(Event::SendLinkTracked {
                link_id,
                data,
                context,
                completion,
            })
            .await?;
        receipt.await
    }

    /// Try to admit a Link send without waiting for capacity.
    ///
    /// A successful return is a receipt, not a transmission result. Await the
    /// receipt for exactly the same completion contract as `send_on_link`.
    /// QueueFull means nothing was admitted and the caller may retry. The
    /// receipt's `packet_hash` matches the packet to its delivery proof.
    pub fn try_send_on_link(
        &self,
        link_id: [u8; 16],
        data: Vec<u8>,
        context: u8,
    ) -> Result<crate::link_send::LinkSendReceipt, crate::link_send::LinkSendError> {
        use crate::link_send::{Completion, LinkSendError};
        let permit = self.tx.link_send_pool().try_acquire()?;
        let tracking = self.tx.link_send_pool().track(link_id, false);
        let (completion, receipt) = Completion::new_tracked(permit, tracking);
        self.tx
            .try_send(Event::SendLinkTracked {
                link_id,
                data,
                context,
                completion,
            })
            .map_err(|error| match error {
                std::sync::mpsc::TrySendError::Full(_) => LinkSendError::QueueFull,
                std::sync::mpsc::TrySendError::Disconnected(_) => LinkSendError::DriverStopped,
            })?;
        Ok(receipt)
    }

    /// Admit a best-effort direct Link datagram without blocking on queue space.
    ///
    /// Success means the driver accepted and encoded the packet. It does not
    /// imply remote delivery, acknowledgement, or interface transmission.
    pub fn try_send_link_datagram(
        &self,
        link_id: [u8; 16],
        data: Vec<u8>,
        context: u8,
        timeout: Duration,
    ) -> Result<(), crate::event::LinkDatagramError> {
        use crate::event::LinkDatagramError;
        if self.reject_new_work_if_draining().is_err() {
            return Err(LinkDatagramError::DriverStopped);
        }
        let (response_tx, response_rx) = std::sync::mpsc::channel();
        self.tx
            .try_send(Event::SendOnLink {
                link_id,
                data,
                context,
                response_tx: Some(response_tx),
            })
            .map_err(|error| match error {
                std::sync::mpsc::TrySendError::Full(_) => LinkDatagramError::DriverQueueFull,
                std::sync::mpsc::TrySendError::Disconnected(_) => LinkDatagramError::DriverStopped,
            })?;
        response_rx
            .recv_timeout(timeout)
            .map_err(|error| match error {
                std::sync::mpsc::RecvTimeoutError::Timeout => LinkDatagramError::AdmissionTimedOut,
                std::sync::mpsc::RecvTimeoutError::Disconnected => LinkDatagramError::DriverStopped,
            })?
    }
}
