# Issue #152: local transmission completion

The async/try API pairs report successful transmission only when the selected
interface writers have written the complete frame to their underlying transports. Neither promises
remote reception or acknowledgement.

```rust,ignore
// Wait for outbound capacity, then wait for the actual write.
node.send_on_link(link_id, payload, context).await?;

// Do not wait for capacity. QueueFull means nothing was admitted.
let receipt = node.try_send_on_link(link_id, payload, context)?;
receipt.await?; // Exactly the same transmission result as send_on_link().

let hash = node.send_packet(&destination, &data).await?;
let receipt = node.try_send_packet(&destination, &data)?;
let hash_for_proof_tracking = receipt.packet_hash();
let same_hash_after_transmission = receipt.await?;

node.announce(&destination, &identity, app_data).await?;
node.try_announce(&destination, &identity, app_data)?.await?;
```

The futures work with any executor. Synchronous callers can use
`node.try_send_on_link(...)?.wait()?`; do not block from driver callbacks.
Migrating the old synchronous `send_on_link()` requires awaiting it or using
the receipt's blocking `wait()`. Merely obtaining a receipt is admission, not
transmission success. The existing `try_send_link_datagram()` remains an
explicitly admission-only, best-effort API for datagram users such as rntun.

`send_packet` and `announce` are now async too. Their old submission-only
behavior is explicitly named `send_packet_queued` and `announce_queued` for
callers that intentionally need best-effort queuing. These compatibility
methods do not confirm transmission. Synchronous callers needing confirmation
can use the `try_*` receipt's `wait()` (never from a driver callback).

Packet and announcement success means every selected local interface writer
completed its write. An error is returned only after all selected writes have
settled; it may mean partial transmission across interfaces. No eligible route
returns `TransmissionError::NoRoute`, not success. This does not wait for remote
delivery, proofs, or announcement relays. Original hops-zero announcements keep
their normal routing policy; relay bandwidth throttling is unchanged. Shared
client replay state is stored with the admitted announcement, so queue rejection
or cancellation before admission cannot update replay state.

The configured driver event capacity bounds outstanding confirmed Link,
packet, and announcement sends together across driver events, pending interface
frames, and writes in progress. Broadcast fanout holds one admission slot until
all selected writes settle. Packet/announcement sends do not affect Link counters.
The async API waits for admission; the try API returns QueueFull immediately.
The driver retains accepted frames when a writer queue is full, preserving
their per-interface order and continuing to process other events. Writer
capacity notifications wake pending work. Completion releases admission space.

Cancellation before admission sends nothing. Dropping an admitted send's
future or receipt does not cancel it. Shutdown resolves pending receipts with
an error. A write error may follow a partial transmission, so callers must not
assume arbitrary errors are safe to retry. Routing/policy rejection and invalid
Links also produce errors instead of successful receipts.

## Per-link send backlog

`node.links()` includes two local send counters on every `LinkInfoEntry`:

- `pending_send_packets`: admitted confirmed sends that have not finished
  writing, including driver backlog, interface queues, and writes in progress.
- `waiting_send_packets`: polled async sends waiting for admission capacity
  (either the outstanding-send budget or the driver event queue).

`node.query_link(link_id)?` returns `Some(LinkInfoEntry)` with the same fields,
or `None` for an unknown link. The controller's link list exposes both counters
as well. These are snapshots, not reservations or remote acknowledgement counts.
They cover `send_on_link` and `try_send_on_link`; Channel counters remain
separate, and the legacy admission-only datagram API is not included.

Unpolled futures are not counted. Cancelling a send before admission removes
its waiting count; dropping an admitted receipt does not remove its pending
count. Completion, failure, and shutdown clear the corresponding counts.

## Regression tests

```sh
cargo test -p rns-net --test e2e issue152 -- --nocapture
```

Two Rust RnsNodes establish an encrypted Link over real loopback TCP. Eight
paced packets verify delivery and payload integrity. A test-only wrapper then
pauses the sender's concrete writer while 4,096 numbered 256-byte payloads
(1 MiB) are admitted. Neither API may complete any send while the writer is
paused. After release, every payload and a final marker must arrive, and all
send completions must succeed. Both tests use the default 256-frame writer
queue; one exercises async sends and the other the try/receipt API.

The wrapper injects no packet loss and paces writes at 2 ms per frame. The
sender has 4,096-event capacity, exactly filled by the burst, and the receiver
has 8,192-event capacity to isolate sender egress from receiver ingress limits.
The paused-writer tests also check the single-link/list snapshots and a further
async send waiting for capacity, including its cancellation. Separate unit
tests exercise full admission capacity, async wakeups, cancellation, writer
flush/error handling, and shutdown. KISS/RNode tests verify that confirmed
sends wait for flow-control readiness before completing.

## Original reproduction (2026-09-08)

Before the fix, the old synchronous API reported success for every send:

| Sender writer queue | Successful send calls | Received burst packets | End marker |
| --- | --- | --- | --- |
| 256 (default) | 4,096 | 257 | Received |
| 4,096 (control) | 4,096 | 4,096, intact and in order | Received |

The default cutoff reproduced repeatedly: one packet was held by the concrete
writer and 256 remained queued. `WouldBlock` discarded the rejected packet;
subsequent packets were discarded during driver backoff. Increasing the queue
was a diagnostic control, not the fix. With default receiver ingress limits,
the control also experienced downstream loss, which is why the test isolates
sender egress from receiver capacity.

This demonstrates a Rust sender mechanism consistent with #152. It does not
recreate the reporter's exact Python RNS 1.5.2 shared-instance topology or add
reliable network delivery to raw Link packets.
