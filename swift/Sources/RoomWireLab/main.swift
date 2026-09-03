import Foundation
import RoomWireProtocol
import RoomWireTransport

// The lab tool: a real host and a real viewer, driven from a terminal.
//
//   roomwire-lab host --name "Lab Host" [--auto-approve] [--seconds N]
//   roomwire-lab view [--host NAME | --first] [--name N] [--seconds N]
//   roomwire-lab selftest
//
// Arguments are parsed by hand. A dependency for six flags would be a
// dependency in the transport product's own package, which is the one place
// this project has decided not to have any.
//
// Terminal needs Local Network permission on macOS 15 for Bonjour to see
// anything at all — it is granted once, in a dialog, on the first run.

// Line buffering, because this tool's whole job is to put a pairing code in
// front of somebody. Redirected to a file or a pager, stdout is block-buffered
// and the code appears when the process exits, which is exactly too late.
setvbuf(stdout, nil, _IOLBF, 0)

let arguments = Array(CommandLine.arguments.dropFirst())

func flag(_ name: String) -> Bool { arguments.contains("--\(name)") }

func option(_ name: String) -> String? {
    guard let i = arguments.firstIndex(of: "--\(name)"), i + 1 < arguments.count else { return nil }
    let value = arguments[i + 1]
    return value.hasPrefix("--") ? nil : value
}

func seconds(default fallback: Double) -> Double {
    option("seconds").flatMap(Double.init) ?? fallback
}

/// A signal handler is the only way to make ^C tear a host down rather than
/// leave a Bonjour advertisement behind, and dispatch's is the one that is safe
/// to do real work in.
func onInterrupt(_ work: @escaping () -> Void) {
    signal(SIGINT, SIG_IGN)
    let source = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
    source.setEventHandler { work(); exit(0) }
    source.resume()
    interruptSource = source
}
var interruptSource: DispatchSourceSignal?

switch arguments.first {
case "selftest":
    exit(Selftest.run())

case "host":
    let name = option("name") ?? "Lab Host"
    let auto = flag("auto-approve")
    let store = URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent(".roomwire-lab/trust.json")
    let trust: any TrustStore = auto ? AlwaysAsk() : FileTrust(url: store)
    let identity: Identity
    do {
        identity = try Identity.load(label: "roomwire-lab-host")
    } catch {
        print("could not load an identity: \(error)")
        exit(1)
    }
    let host = Host(name: name, identity: identity, trust: trust)
    print("host \"\(Packet.clampName(name))\"  fingerprint \(identity.fingerprint.hexString)")
    print(auto ? "auto-approving every viewer — the code is still shown" : "trust file \(store.path)")

    host.onInvite = { invite in
        print("\n  \(invite.peer.displayName) wants to join")
        print("  code on both screens:  \(invite.code)")
        print("  fingerprint \(invite.peer.fingerprint.hexString)")
        if auto {
            print("  admitting (--auto-approve)\n")
            invite.respond(true)
        } else {
            print("  approve? [y/N] ", terminator: "")
            let answer = readLine()?.lowercased().hasPrefix("y") ?? false
            print(answer ? "  admitted\n" : "  refused\n")
            invite.respond(answer)
        }
    }
    host.onConnected = { peers in
        print("connected: \(peers.isEmpty ? "nobody" : peers.map(\.displayName).joined(separator: ", "))")
    }
    host.onPacket = { peer, data in
        print("  <- \(peer.displayName): \(describe(data))")
    }
    do {
        try host.start()
    } catch {
        print("could not start: \(error)")
        exit(1)
    }
    print("advertising \(name) over _roomwire._tcp — ^C to stop")
    onInterrupt { host.stop(); print("\nstopped") }
    if let limit = option("seconds").flatMap(Double.init) {
        DispatchQueue.main.asyncAfter(deadline: .now() + limit) { host.stop(); exit(0) }
    }
    dispatchMain()

case "view":
    let wanted = option("host")
    let display = option("name") ?? Host.deviceName()
    let identity: Identity
    do {
        identity = try Identity.load(label: "roomwire-lab-viewer")
    } catch {
        print("could not load an identity: \(error)")
        exit(1)
    }
    let viewer = Viewer(identity: identity)
    print("viewer \"\(Packet.clampName(display))\"  fingerprint \(identity.fingerprint.hexString)")

    let joined = NSLock()
    var attempted = false
    viewer.onHosts = { hosts in
        print("hosts: \(hosts.isEmpty ? "none yet" : hosts.map(\.name).joined(separator: ", "))")
        joined.lock()
        defer { joined.unlock() }
        guard !attempted else { return }
        let pick = wanted.flatMap { name in hosts.first { $0.name == name } } ?? (flag("first") ? hosts.first : nil)
        guard let pick else { return }
        attempted = true
        print("joining \(pick.name)…")
        viewer.join(pick, token: UUID(), name: display)
    }
    viewer.onState = { state in
        switch state {
        case .awaitingApproval(let host, let code, let changed):
            print("\n  waiting for \(host.name) to approve")
            print("  code on both screens:  \(code)")
            if changed { print("  WARNING: this host's certificate is not the one it had last time") }
            print("")
        case .connected(let peer):
            print("connected to \(peer.displayName)")
        case .failed(let why):
            print("failed: \(why)")
        default:
            break
        }
    }
    var frames = 0
    viewer.onPacket = { data in
        if (data.first ?? 0xFF) <= 1, Packet.decode(data) != nil {
            frames += 1
            if frames % 30 == 1 { print("  -> \(frames) frames") }
        } else {
            print("  -> \(describe(data))")
        }
    }
    viewer.startBrowsing()
    onInterrupt { viewer.leave(); print("\nleft") }
    DispatchQueue.main.asyncAfter(deadline: .now() + seconds(default: 3600)) {
        viewer.leave()
        print("done — \(frames) frames")
        exit(0)
    }
    dispatchMain()

default:
    print("""
    roomwire-lab — the transport, driven from a terminal

      roomwire-lab host --name "Lab Host" [--auto-approve] [--seconds N]
      roomwire-lab view [--host NAME | --first] [--name N] [--seconds N]
      roomwire-lab selftest

    Terminal needs Local Network permission for Bonjour to find anything.
    """)
    exit(arguments.isEmpty ? 0 : 2)
}

/// A one-line description of a control message, for the terminal.
func describe(_ data: Data) -> String {
    switch Packet.decodeMessage(data) {
    case .video(let frame): return "video \(frame.keyframe ? "keyframe" : "delta") seq \(frame.sequence), \(data.count) bytes"
    case .cursor(_, _, let x, let y): return String(format: "cursor %.3f, %.3f", x, y)
    case .needKeyframe: return "needKeyframe"
    case .needRefresh: return "needRefresh"
    case .identify: return "identify"
    case .reaction(let kind): return "reaction \(kind)"
    case .mark(let kind, _, _): return "mark \(kind)"
    case .requestControl: return "requestControl"
    case .some(let other): return "\(other)"
    case .none: return "\(data.count) bytes we could not read"
    }
}
