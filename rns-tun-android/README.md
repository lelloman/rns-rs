# rntun for Android

This directory contains both the portable JNI library and the Android client.
The application owns a private Reticulum node, supports multiple client
profiles, and uses Android's `VpnService` for an all-apps IPv4 tunnel.

## Build

Install JDK 17, Android SDK 36, NDK 28.2.13676358, Rust 1.96, the four Android
Rust targets, and `cargo-ndk` 4.1.2. Then run `./gradlew assembleDebug` from this directory.
The `buildRust` task produces `librns_tun_android.so` for arm64-v8a,
armeabi-v7a, x86, and x86_64.

The repository intentionally does not commit generated native libraries. A
release build should be signed by the distributor; no app-store-specific API
or dependency is required.

## Security model

Every profile is a client profile in version 1. Full-tunnel profiles stay
fail-closed while connecting or reconnecting, accept only gateway-approved DNS,
and never call `allowBypass`. One application identity is shared by all
profiles. Profile and identity exports are encrypted using Argon2id (32 MiB,
three iterations, one lane) and XChaCha20-Poly1305.

Android gateway mode is reserved in the persisted schema as a role, but is a
version 2 feature because it also needs a userspace IPv4 forwarding/NAT engine.
