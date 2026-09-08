# Issue #152: Link transmission completion

Both APIs report successful transmission only when the interface writer has
written the complete frame to its underlying transport. Neither promises
remote reception or acknowledgement.

```rust,ignore
// Wait for outbound capacity, then wait for the actual write.
node.send_on_link(link_id, payload, context).await?;

// Do not wait for capacity. QueueFull means nothing was admitted.
let receipt = node.try_send_on_link(link_id, payload, context)?;
receipt.await?; // Exactly the same transmission result as send_on_link().
```

The futures work with any executor. Synchronous callers can use
`node.try_send_on_link(...)?.wait()?`; do not block from driver callbacks.
Migrating the old synchronous `send_on_link()` requires awaiting it or using
the receipt's blocking `wait()`. Merely obtaining a receipt is admission, not
transmission success. The existing `try_send_link_datagram()` remains an
explicitly admission-only, best-effort API for datagram users such as rntun.

The configured driver event capacity also bounds outstanding confirmed Link
sends across driver events, pending interface frames, and writes in progress.
The async API waits for admission; the try API returns QueueFull immediately.
The driver retains accepted frames when a writer queue is full, preserving
their per-interface order and continuing to process other events. Writer
capacity notifications wake pending work. Completion releases admission space.

Cancellation before admission sends nothing. Dropping an admitted send's
future or receipt does not cancel it. Shutdown resolves pending receipts with
an error. A write error may follow a partial transmission, so callers must not
assume arbitrary errors are safe to retry. Routing/policy rejection and invalid
Links also produce errors instead of successful receipts.

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

The wrapper injects no packet loss and paces writes at 2 ms per frame. Both
nodes have 8,192-event capacity so the whole test burst can be admitted and
receiver ingress limits do not obscure the sender regression. Separate unit
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
