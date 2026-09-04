#!/bin/sh
# Self-checks for the Swift implementation. Built unoptimised so the assertions
# stay live. Run from anywhere: ./swift/check.sh from the repo root, or
# ./check.sh from inside swift/.
#
# These compile source files, not the package — `swiftc a.swift b.swift` makes
# one ad-hoc module and does not care about Package.swift. That is deliberate:
# the checks were written before this was a package and they keep working
# exactly as they were, `public` and all.
set -e
cd "$(dirname "$0")"
out=$(mktemp -d)
src=Sources/RoomWireProtocol

# The wire format parses untrusted bytes off the network.
swiftc $src/Packet.swift Checks/PacketCheck.swift -o "$out/packet"
"$out/packet"

# The same format, frozen as bytes, because Swift is not its only
# implementation — kotlin/ speaks it too. Regenerate and diff: a wire-format
# change must show up as a diff in a checked-in file, not as a corrupt frame on
# a phone three months from now. If this fails and the change was deliberate,
# commit the new protocol/vectors.txt *with* the Kotlin side.
swiftc $src/Packet.swift $src/Chunk.swift $src/MediaSeal.swift $src/Pairing.swift \
    $src/BulkSeal.swift $src/Transfer.swift \
    Checks/PacketVectors.swift -o "$out/vectors"
"$out/vectors" > "$out/vectors.txt"
if ! diff -u ../protocol/vectors.txt "$out/vectors.txt"; then
    echo "check.sh: the wire format moved. See the diff above."
    exit 1
fi

# The four state machines, frozen as behaviour. Bytes cannot express "and
# then"; a transcript can. Same discipline as the vectors: regenerate, diff,
# and a change must land in a checked-in file alongside the Kotlin side.
swiftc $src/Packet.swift $src/ChainGate.swift $src/Pacer.swift $src/CursorMotion.swift $src/Pointer.swift \
    $src/Chunk.swift $src/MediaSeal.swift $src/Pairing.swift Checks/TranscriptVectors.swift -o "$out/transcripts"
"$out/transcripts" > "$out/transcripts.txt"
if ! diff -u ../protocol/transcripts.txt "$out/transcripts.txt"; then
    echo "check.sh: behaviour moved. See the diff above."
    exit 1
fi

# A stalled radio delivers its backlog in a burst; the pacer must skip it, not
# replay it at fast-forward.
swiftc $src/Pacer.swift Checks/PacerCheck.swift -o "$out/pacer"
"$out/pacer"

# The pointer is sampled at 60 Hz, drawn at up to 120, and delivered
# unreliably: sequencing decides what to believe, the glide what to draw in
# between.
swiftc $src/CursorMotion.swift Checks/CursorMotionCheck.swift -o "$out/cursormotion"
"$out/cursormotion"

# Losing a frame and breaking the stream are not the same event: half the
# frames are an enhancement layer nothing is built on.
swiftc $src/ChainGate.swift Checks/ChainGateCheck.swift -o "$out/chaingate"
"$out/chaingate"

# A tap that clicks, a drag that drags, and a button that never sticks down.
# Both sides of the pointer contract: a finger read into a button mask, and a
# mask read back into the edges a desktop wants.
swiftc $src/Packet.swift $src/Pointer.swift Checks/PointerCheck.swift -o "$out/pointer"
"$out/pointer"

# The media lane's pure half: a frame cut into datagrams comes back
# byte-identical in any order, a hole is never delivered, the envelope refuses a
# flipped bit anywhere, and the replay window forgets exactly what it should.
swiftc $src/Packet.swift $src/Chunk.swift $src/MediaSeal.swift Checks/MediaLaneCheck.swift -o "$out/medialane"
"$out/medialane"

# And the transport itself, over real Bonjour and real sockets, in one process:
# two identities that have never met, a pairing code compared on both sides,
# approval, refusal, fan-out, backpressure and a rejoin that asks nobody. This
# is the one check that builds the package rather than compiling files, and the
# one that needs a keychain — a temporary one, deleted at the end.
#
# It also needs Local Network permission for the terminal it runs in, because
# Bonjour is how the viewers find the host. macOS asks once.
swift run -c debug roomwire-lab selftest

echo "swift: all checks passed"
