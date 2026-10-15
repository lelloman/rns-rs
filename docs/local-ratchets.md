# Local Destination Ratchets

An application can opt one of its `IN SINGLE` destinations into rotating
packet-encryption keys. Rotation is announced along with the destination, and
the ring of retained keys lets delayed packets still decrypt. The format is
wire-compatible with Python Reticulum's ratchets; this page is about the Rust
API and its storage guarantees.

## Try it

The `message` example runs two peers with persistent ratchet files in a
temporary directory:

```bash
cargo run -p rns-net --example message
```

## Using ratchets in an application

Keep the application's identity and private ratchet file across restarts.
Create the owner, attach it before announcing, and decrypt delivered packets
with the same owner:

```rust,ignore
let ratchets = rns_net::LocalRatchets::persistent(
    &destination,
    rns_crypto::identity::Identity::from_private_key(&identity.get_private_key().unwrap()),
    app_state.join("destination-ratchets"),
)?;
ratchets.set_interval(30 * 60)?;
ratchets.set_retained(512)?;
ratchets.enforce(); // optional: reject packets encrypted to the identity key
node.attach_local_ratchets(ratchets.clone())?;
node.register_destination(destination.hash.0, destination.dest_type.to_wire_constant())?;
node.announce(&destination, &identity, None).await?;

// In the receive path, after unpacking the raw packet:
let decrypted = ratchets.decrypt(&packet.data)?;
// decrypted.plaintext and decrypted.ratchet_id belong to this result only.
```

## Policy

| Setting | Default | Range and notes |
|---------|---------|-----------------|
| Rotation interval | 30 minutes | Rotation happens on a fresh announcement once the interval has elapsed. The first announcement after a reload rotates too. A backward clock jump postpones rotation |
| Retained keys | 512, including the current key | 1 to 4096. Count-based, independent of received public-key expiry. Smaller rings mean less decryption work and less history, but reject delayed packets sooner |
| Enforcement | off | When on, packets encrypted to the bare identity key are rejected |

Policy is not stored in the file. Reapply interval, retention, and enforcement
every time an owner is reopened. Announcements carrying a ratchet have 32 fewer
bytes available for application data. Link key exchange is unaffected.

## Storage

Private files are signed MessagePack, compatible with Python's retained-key
files, plus a destination binding that Rust validates when present. Legacy
Python files carry no binding: their signature identifies the owner, not the
destination, so assign them to the right destination yourself.

The filesystem store uses Unix advisory locking, private file permissions,
atomic replacement, and synchronization. Keep these files outside the
received-public-ratchet cache. They are not encrypted at rest, and backups
retain keys, which limits what retiring a key buys you. In-memory key buffers
are zeroized on retirement and drop; that cannot reach backups or filesystem
history.

Only one writer may own a private file. Do not share an active file with a
Python process, which does not honour the Rust lock. Other platforms can
implement `LocalRatchetStore`; `MemoryRatchetStore` explicitly opts into
losing keys on restart.

## Failure behaviour

A store failure blocks new announcements, preserves existing receive state,
and leaves enforcement on. Fix the storage problem, then call
`ratchets.recover()` to reload and durably reconcile the file. Missing or
corrupt history requires explicit operator recovery and is never silently
recreated.

The attached owner is shared with reconnect replay and survives destination
unregistration until node shutdown. Queued announcements keep their advertised
keys retained until local writes complete, so rotation and pruning can return
`WouldBlock` until then. Obsolete cached announcements are suppressed.

Raw packet callbacks and transport proofs do not imply successful decryption:
call `ratchets.decrypt` before accepting data. Enforcement does not filter raw
callbacks.

## Sending to a ratcheted remote destination

Received public ratchets are cached through `NodeConfig::ratchet_store`.
File-configured nodes set this up automatically. An application that builds a
custom `NodeConfig` must configure that cache itself, as the `message` example
does. Enabling a local private owner does not configure remote-key storage.

## Provenance

Local ratchet generation and custom retention were completed on 2026-10-03 as
part of the Reticulum 1.5.0 rgit porting queue; see the
[1.5.0 rgit audit](upstream-parity/reticulum-1.5.0-rgit-audit.md).
