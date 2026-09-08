# One radio: why the iPhone leaves AWDL, and how it joins without a certificate

*Design record, 8 September 2026. Covers the investigation, the decision, the
protocol and module changes in roomwire `06ca499`, the app changes that use
them, what was verified and how, and what is still only predicted.*

## 1. The problem, in numbers

An Android viewer on the same Mac as an iPhone was "very jittery, not usable",
while the iPhone was fine. The flight recorder (one clock, every viewer) and a
repeatable streaming test on wired Androids said this:

| Configuration | Android shown | lost | lateness |
|---|---|---|---|
| Android on the office AP, Mac on the office AP, iPhone present | 53–72% | 2–3% | 87–159 ms p50, holds of 300–500 ms |
| Android as a client of its **own 5 GHz hotspot**, Mac a client of it, **no iPhone** | 100% | 0% | 6 ms |
| Same, iPhone streaming over AWDL at the same time | collapses | – | 300–500 ms holds return |
| Both Androids as plain clients of one office AP, Mac a client too, no iPhone | 96–99% | ~0% | AP-limited |

So the Android path was never the codec, the pacer or the send path. With the
iPhone absent, a direct 5 GHz link was perfect. With the iPhone present, it was
not — and the iPhone was not on that link at all: `netstat -ib` showed 16–22 GB
leaving `awdl0`. The iPhone rides Apple Wireless Direct Link, a Mac↔phone link
that never touches the access point.

## 2. The cause: one radio, time-shared

A consumer Mac has one Wi-Fi radio. This one is a Broadcom BCM4388 (`0x14E4 /
0x4388`), dual-band but not *simultaneous* dual-band: it is tuned to one channel
at a time. AWDL does not get its own radio. It time-shares the single one with
the infrastructure link, on a fixed schedule.

The schedule is measured, not guessed. Stute, Kreitschmann and Hollick took
AWDL apart in *One Billion Apples' Secret Sauce* (MobiCom 2018,
[arXiv:1808.03156](https://arxiv.org/abs/1808.03156)), and their Table 2 is the
load-bearing fact for everything here. AWDL divides time into a 16-slot channel
sequence of about 1.05 s; in each slot the radio is either on a "social" channel
(6, 44 or 149) for AWDL, or on the channel the infrastructure link uses. The
fraction spent away from the infrastructure channel depends on AWDL's state:

| AWDL state | slots off the infrastructure channel |
|---|---|
| Low Power (idle) | 4 of 16 ≈ 25% |
| Idle | 6 of 16 ≈ 37.5% |
| Data + Infra | 8 of 16 ≈ 50% |
| Data | 12 of 16 ≈ 75% |

Two consequences the paper states outright and we rely on:

- **§8.2:** "even in the so-called low power state, AWDL is active for at least
  25% of the time during which the Wi-Fi radio is active." Idle is not free.
- **§7.5:** "there is always a switch to channel 6 in slot 9" — one 65 ms hole
  per cycle no alignment removes, plus an 8 ms switch and a 3 TU guard each way
  (§8.1). Even a Mac whose office AP sat *on* a social channel would still lose
  that slot.

That is the 300–500 ms hold. While the radio is off serving AWDL, nothing
reaches the Android; the datagrams queue and arrive in a burst when the radio
comes back. And it is architectural: no buffer, codec change or FEC on the
Android side can fill a hole the radio is physically absent for.

The paper also says (§4, §8.3) that AWDL is **inactive by default** and is
"activated only on demand and deactivated once no more traffic is registered".
Something has to turn it on. On this app, the Mac host does:
MultipeerConnectivity's advertiser and every `includePeerToPeer = true` on a
`NWParameters` are what wake `awdl0`. Apple's own [TN3213](https://developer.apple.com/documentation/technotes/tn3213-moving-from-multipeer-connectivity-to-network-framework)
says the same in 2026 — "Enabling peer-to-peer Wi-Fi can reduce network
performance both for your app and for other apps on the device" — and a DTS
thread from March 2026 is blunter still: "Multipeer Connectivity won't help. It
uses the same peer-to-peer Wi-Fi infrastructure as Network framework."

## 3. What we ruled out, and why

Before building anything, twelve escape routes were researched against primary
sources and each given two adversarial reviews. The ones that do **not** work,
so nobody reopens them:

- **Make AWDL and the infrastructure link coexist better** — channel alignment,
  throttling the iPhone, scheduling Android sends into the gaps. All capped by
  the mandatory channel-6 slot at a ~65–85 ms hole per second, above the 20 ms
  bar, and the Mac cannot even observe its own channel hops from an app
  (`CWEventType` has no case for it).
- **A second radio for the Mac** — USB Wi-Fi adapters have no DriverKit family
  on Apple silicon (`NetworkingDriverKit` is Ethernet only); newer Macs are
  still single-radio; Wi-Fi 7 MLO needs an AP peer that neither AWDL nor a phone
  hotspot is.
- **Bluetooth as the Android's video lane** — its whole one-way ceiling
  (~2 Mbit/s) is below the stream's own bitrate, and it needs a runtime
  permission the app will not take.
- **USB tether the Android** — proven to work on the bench, but the product is
  wireless; a cable is not the experience. (Recorded as a diagnostic only.)

What is left is the only thing that removes the variable rather than shrinking
it: **stop activating AWDL, and put the iPhone on ordinary Wi-Fi like everyone
else.** That is what this change builds.

## 4. The obstacle to putting the iPhone on Wi-Fi: identity

RoomWire already had an infrastructure transport — Android uses it. The reason
the iPhone did not was not the media lane (that has been cert-free and
iOS-linkable since `cea6681`), it was the **control lane's identity**.

Every RoomWire viewer proves who it is with a self-signed client certificate
inside mutual TLS. The host pins SHA-256 of that certificate's DER; that
fingerprint *is* the viewer's identity, on first-use trust with the six-char
pairing code covering the first time. macOS mints the certificate through
swift-certificates; Android mints one in its Keystore. But **iOS cannot mint a
certificate without swift-certificates, which pulls BoringSSL** — a new
encryption dependency on an App Store binary that has already been rejected
twice on unrelated grounds and that we are keeping clean. `Security.framework`
imports a DER certificate but has no public call that *creates* one; DTS
confirms the only supported path is "generate the key, send the public half to
your CA" — and there is no CA here by design.

So the iPhone has a key and nothing to wrap it in.

## 5. The design: a second identity, proved one message later

The fix is to let a viewer be identified by a **bare P-256 key** instead of a
certificate. Its fingerprint is SHA-256 of the key's X9.63 public representation
(65 bytes, `0x04` first), standing in exactly the place SHA-256 of a
certificate's DER stands for everyone else. The host stores a fingerprint either
way and cannot tell, once a viewer is admitted, which kind it was.

A certificate proves possession of its key *inside* the TLS handshake. A bare
key has to prove it somewhere, so it proves it one message later, in the
pairing handshake that was already there:

```
certificate viewer            key viewer (iPhone)
------------------            -------------------
hello        ───►             helloKey     ───►      (+ 65-byte public key)
      ◄─── hostNonce                ◄─── hostNonce
reveal       ───►             revealSigned ───►      (+ 64-byte signature)
      ◄─── welcome                  ◄─── welcome
```

Two additive messages carry it:

- **`helloKey` (id 30)** is `hello` plus the viewer's 65-byte public key. Its
  fingerprint is derived from that key. The decoder checks the X9.63 shape;
  only CryptoKit, in the transport, decides whether the point is on the curve.
- **`revealSigned` (id 31)** is `reveal` plus a 64-byte raw ECDSA signature
  (r ‖ s) over `Pairing.proof` = **hostNonce ‖ hostFingerprint ‖ token**.

`Pairing.proof` is what makes the signature safe, and each part closes one door:

- **hostNonce** is the host's own 16 bytes, fresh per connection, so a captured
  signature replays to nobody a moment later.
- **hostFingerprint** binds the proof to *this* Mac, so a signature made for one
  host is meaningless to another — this is what stops a machine-in-the-middle
  relaying the proof to a second host.
- **token** ties the proof to the commitment that opened this very handshake, so
  it cannot be lifted onto a different pairing.

The host believes **nothing** about the key until that signature verifies
against `Pairing.proof` computed with the host's own nonce and fingerprint. Only
then does the key's fingerprint become the viewer's identity and get pinned, and
from there the trust store, the pairing code, approval, and the media lane are
byte-for-byte what they always were.

The pairing code's two-sided commitment property is untouched: the viewer still
commits to its token in `helloKey` before the host sends its nonce, so neither
side chooses its contribution last, and six characters are still worth 2⁻³⁰ per
attempt rather than a birthday search. (See `Pairing.swift` for that argument in
full.)

### Two listeners, not one polite one

The host would ideally ask every viewer for a certificate and simply accept not
getting one. The macOS API for that —
`sec_protocol_options_set_peer_authentication_optional` — **does not exist on
macOS** (it is iOS-only). So the host runs two `NWListener`s instead:

- `_roomwire._tcp` — mutual TLS, a client certificate **required**. Certificate
  viewers (Android, and Macs viewing Macs) as before.
- `_roomwirek._tcp` — the host presents its certificate and **asks for none**.
  Key viewers (the iPhone) go here and prove their key in `revealSigned`.

Same host, same identity, same trust store, same session table, same media lane.
Only the first two control messages and the service name differ. A viewer
browses the one service its identity can speak.

## 6. The module split: what iOS links

The dependency line now runs cleanly through three products:

| product | holds | depends on |
|---|---|---|
| `RoomWireProtocol` | wire format, pacer, chunker, seals, pairing — pure values | nothing |
| `RoomWireLink` | control lane, TLS params, `Viewer`, `ViewerIdentity`, UDP receiver | RoomWireProtocol |
| `RoomWireTransport` | `Host`, `OutboundMedia`, `Identity` (minting) | RoomWireLink + swift-certificates |

The old `RoomWireMedia` (just the UDP receiver) became `RoomWireLink` and
absorbed everything a viewer needs that does **not** touch a certificate
library: `ControlLane`, `TLS`, `Peer`, `Viewer`, and the new `ViewerIdentity`.
The one thing that genuinely needs swift-certificates — `Identity.load`, which
mints the self-signed certificate — stays in `RoomWireTransport` with the host.

iOS links `RoomWireProtocol` + `RoomWireLink` and gets a whole viewer.
`RoomWireTransport` stays macOS-only (`destinationFilters: [macOS]` in
`project.yml`). A `ViewerIdentity` is one of:

- `.certificate(sec_identity_t, fingerprint:)` — from `Identity.viewer` on
  macOS, or Android's Keystore.
- `.key(SigningKey)` — a P-256 key, in the **Secure Enclave** where the device
  has one (the private half never leaves the chip, the same property Android's
  Keystore gives) and in software otherwise.

## 7. `Reach`: the opt-in that was always on

The last piece is why the Mac was activating AWDL for viewers that did not want
it. Every RoomWire lane set `includePeerToPeer = true` unconditionally — on the
listener, the browser and every dial. That one line is what let the single radio
be time-shared away from the Android's channel.

It is now a `Reach`:

- **`.infrastructure`** (default) — the network the devices are already on.
  Apple's own default for `NWParameters`, and the only choice that leaves the
  Mac's radio on the channel the Android is streaming over.
- **`.peerToPeer`** — adds AWDL, for a room with no infrastructure at all.

The iPhone viewer and the Mac host both take the default. Nothing in the app
asks for `.peerToPeer`; it exists for a future "no Wi-Fi in the room" mode.

## 8. How the app uses it

**iPhone / iPad (`Session.swift`).** `startBrowsing()` now starts a
`RoomWireLink.Viewer` with a `.key` identity (from `SigningKey.load`, stored per
install) first. MultipeerConnectivity browsing starts **only** if RoomWire finds
nothing for ~4 seconds — a Mac on another network, or one running a build from
before this. Because MC browsing is itself what wakes AWDL, it is never started
on speculation, and it is stopped again the moment a Mac appears over Wi-Fi.
RoomWire hosts and MC hosts merge into one `hosts` list, de-duplicated by name
so the same Mac is never shown twice.

`WatchView` gained the one screen MultipeerConnectivity never needed: the
six-character pairing code, shown large while the presenter decides, and a plain
sentence when a join is declined or fails.

**Mac (`RoomWireBridge.swift`).** Unchanged in behaviour — it hosts, and the
second listener comes for free from the transport. It gained one `import
RoomWireLink`, since `Peer`, `Reliability` and `TrustStore` moved there.

The `MCPeerID`-as-identity-token shim (documented at length in
`RoomWireBridge`) is reused verbatim on the viewer side: a RoomWire host wears a
locally minted `MCPeerID` so `WatchView` can key on one type, and it is never
handed to `MCSession`.

## 9. What was verified

- **`roomwire/check.sh` green.** Packet checks, pacer, cursor, chain-gate,
  pointer, media lane; the wire-format vectors (233 → **246** rows) and the
  behaviour transcripts regenerated and diffed; the Swift selftest over real
  Bonjour and real sockets; and the Kotlin `:protocol:test` replaying the same
  vectors. Both languages agree.
- **The selftest now runs a key viewer (D) beside the certificate viewers.** It
  is found on the second service, shows a pairing code both ends agree on, is
  pinned by **its key's fingerprint**, receives the 200 KB fan-out frame, and is
  let back in on a fresh token without anyone being asked — the whole
  remembered-by-fingerprint path, on a bare key.
- **The iOS binary stays BoringSSL-free.** `nm` on the Release build with the
  full RoomWire viewer linked finds **0** BoringSSL / X509 / SwiftASN1 / NIOSSL
  / RoomWireTransport symbols and 637 `RoomWireLink` symbols; `otool -L` links
  no crypto beyond system CryptoKit. The App Review encryption posture is
  unchanged (`ITSAppUsesNonExemptEncryption` stays false; Apple OS crypto is
  export-exempt).
- **macOS host builds and links** against the new module graph.
- `roomwire-lab view --key` joins from a terminal exactly as an iPhone would.

## 10. What is still only predicted

Everything above is verified at the build-and-socket level on one machine.
**Not yet measured on the real phones:**

- That an iPhone on ordinary Wi-Fi, with AWDL never activated, actually holds
  the Android at hotspot class in the same room. The mechanism says it must —
  no AWDL, no time-sharing — but the flight recorder has not seen it yet.
- The iPhone's own numbers as a Wi-Fi viewer. It moves from a private AWDL link
  to a shared one, and inherits whatever the access point's jitter is. It must
  be benched, not assumed good.
- The product topology (phone's 5 GHz hotspot with the phone's Wi-Fi STA off, or
  everyone on the office AP) and its fallbacks.

The one-line bench check, once the phones are back: iPhone joins over
`_roomwirek._tcp` with AWDL confirmed idle (`netstat -I awdl0 -w 1` at zero),
Android streams on its hotspot, and `flight-peers.py` reads the Android at
0% lost and the iPhone in the same class.

## 11. Files

- Protocol: `RoomWireProtocol/Packet.swift` (ids 30/31, `highestKnownId` 31),
  `Pairing.swift` (`proof`); mirrored in `kotlin/protocol/Packet.kt`,
  `Pairing.kt`. Vectors in `protocol/vectors.txt`.
- Link: `RoomWireLink/` — `ViewerIdentity.swift` (new), `Viewer.swift`,
  `TLS.swift`, `ControlLane.swift`, `Peer.swift` (`Reach`, `Bonjour.keyType`),
  `InboundMedia.swift`.
- Transport: `RoomWireTransport/Host.swift` (two listeners, the signed
  handshake), `Identity.swift` (`.viewer`), `MediaLane.swift` (reach).
- App: `apple/App/Shared/Session.swift` (the iPhone viewer),
  `apple/App/Viewer/WatchView.swift` (pairing code), `apple/Support/Info.plist`
  (`_roomwirek._tcp`), `apple/App/Host/RoomWireBridge.swift` (import).
- Commits: roomwire `06ca499` (protocol + link + transport + selftest),
  `eca8a0b` (README). App changes on `android-control`.
