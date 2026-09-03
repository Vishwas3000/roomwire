import CoreMedia
import Foundation
import RoomWireProtocol
import VideoToolbox

/// Runs arriving frames through the hardware H.264 decoder, so a run can say
/// "these decoded" rather than "these arrived".
///
/// That distinction is the entire reason this exists. A frame that reassembles
/// to the right number of bytes proves the transport and proves nothing about
/// the bitstream: parameter sets can be missing, the AVCC length prefixes can
/// be wrong, a keyframe can be truncated by a slice that never came. All of
/// those arrive as a perfectly good `Data` and none of them is a picture. When
/// a phone at the far end shows black, the first question is which half is
/// broken, and this answers it on the Mac before anyone picks up the phone.
final class Decoder {
    private(set) var decoded = 0
    private(set) var failed = 0
    /// Every distinct status the decoder answered with, and how often. A count
    /// of failures says something is wrong; the codes say what.
    private var statuses: [OSStatus: Int] = [:]
    private var session: VTDecompressionSession?
    private var format: CMVideoFormatDescription?
    private let lock = NSLock()

    /// One `Packet` message. Returns a one-line verdict when there is something
    /// worth saying, and nil for the ordinary case of a frame that decoded.
    func admit(_ data: Data) -> String? {
        guard let frame = Packet.decode(data) else { return "a video packet that would not parse" }

        // Parameter sets ride with every keyframe, so a session can be built
        // from the first one that arrives and rebuilt if they ever change.
        if let sps = frame.sps, let pps = frame.pps {
            if let made = makeFormat(sps: sps, pps: pps), made != format {
                format = made
                teardown()
                session = makeSession(made)
            }
        }
        guard let session, let format else {
            // Not an error on its own: a viewer that joins mid-GOP waits for
            // the next keyframe, which is exactly what needKeyframe asks for.
            return frame.keyframe ? "a keyframe arrived with no parameter sets" : nil
        }

        guard let sample = makeSample(frame.payload, format: format) else {
            return "could not wrap \(frame.payload.count) bytes as a sample buffer"
        }
        var flags = VTDecodeInfoFlags()
        let status = VTDecompressionSessionDecodeFrame(
            session, sampleBuffer: sample,
            flags: [._EnableAsynchronousDecompression], frameRefcon: nil, infoFlagsOut: &flags)
        if status != noErr {
            lock.lock(); failed += 1; lock.unlock()
            return "the decoder refused a frame (status \(status))"
        }
        return nil
    }

    var summary: String {
        lock.lock(); defer { lock.unlock() }
        let why = statuses.sorted { $0.value > $1.value }
            .map { "\(name($0.key))x\($0.value)" }.joined(separator: " ")
        return "\(decoded) decoded, \(failed) refused" + (why.isEmpty ? "" : " [\(why)]")
    }

    /// The handful of VideoToolbox codes that actually turn up here, by name,
    /// because -17694 in a log is a search and "referenceMissing" is an answer.
    private func name(_ status: OSStatus) -> String {
        switch status {
        case -17694: return "referenceMissing "
        case -12909: return "badData "
        case -12911: return "malformedData "
        case -8969: return "badDataFormat "
        case -8960: return "badData8960 "
        case -12912: return "dataNotReady "
        default: return "status\(status) "
        }
    }

    func finish() {
        if let session { VTDecompressionSessionWaitForAsynchronousFrames(session) }
        teardown()
    }

    private func teardown() {
        if let session { VTDecompressionSessionInvalidate(session) }
        session = nil
    }

    private func makeFormat(sps: Data, pps: Data) -> CMVideoFormatDescription? {
        var out: CMVideoFormatDescription?
        let made = sps.withUnsafeBytes { spsRaw in
            pps.withUnsafeBytes { ppsRaw -> OSStatus in
                let pointers = [spsRaw.baseAddress!.assumingMemoryBound(to: UInt8.self),
                                ppsRaw.baseAddress!.assumingMemoryBound(to: UInt8.self)]
                let sizes = [sps.count, pps.count]
                return CMVideoFormatDescriptionCreateFromH264ParameterSets(
                    allocator: kCFAllocatorDefault, parameterSetCount: 2,
                    parameterSetPointers: pointers, parameterSetSizes: sizes,
                    // The payload is AVCC — four-byte lengths in front of each
                    // NAL unit — which is what Packet carries and what the
                    // encoder produced.
                    nalUnitHeaderLength: 4, formatDescriptionOut: &out)
            }
        }
        return made == noErr ? out : nil
    }

    private func makeSession(_ format: CMVideoFormatDescription) -> VTDecompressionSession? {
        var out: VTDecompressionSession?
        var callback = VTDecompressionOutputCallbackRecord(
            decompressionOutputCallback: { refcon, _, status, _, image, _, _ in
                guard let refcon else { return }
                let decoder = Unmanaged<Decoder>.fromOpaque(refcon).takeUnretainedValue()
                decoder.lock.lock()
                if status == noErr, image != nil {
                    decoder.decoded += 1
                } else {
                    decoder.failed += 1
                    decoder.statuses[status, default: 0] += 1
                }
                decoder.lock.unlock()
            },
            decompressionOutputRefCon: Unmanaged.passUnretained(self).toOpaque())
        let made = VTDecompressionSessionCreate(
            allocator: kCFAllocatorDefault, formatDescription: format,
            decoderSpecification: nil, imageBufferAttributes: nil,
            outputCallback: &callback, decompressionSessionOut: &out)
        return made == noErr ? out : nil
    }

    /// The block buffer owns its bytes, and that is the whole point of the way
    /// this is written.
    ///
    /// The obvious version passes a local `[UInt8]` as `memoryBlock` with
    /// `kCFAllocatorNull`, which tells Core Media not to take ownership — so
    /// the array is freed the moment this function returns, while the
    /// asynchronous decoder still holds a pointer into it. That decodes
    /// whatever the allocator has since put there, which is `badData` on
    /// almost every frame and, once in a while, a frame that works. Measured:
    /// two frames out of thirty-one. It reads as a broken encoder and is not.
    private func makeSample(_ payload: Data, format: CMVideoFormatDescription) -> CMSampleBuffer? {
        var block: CMBlockBuffer?
        guard CMBlockBufferCreateWithMemoryBlock(
            allocator: kCFAllocatorDefault, memoryBlock: nil, blockLength: payload.count,
            blockAllocator: kCFAllocatorDefault, customBlockSource: nil,
            offsetToData: 0, dataLength: payload.count, flags: 0, blockBufferOut: &block) == noErr,
            let block else { return nil }
        guard payload.withUnsafeBytes({ raw in
            CMBlockBufferReplaceDataBytes(with: raw.baseAddress!, blockBuffer: block,
                                          offsetIntoDestination: 0, dataLength: payload.count)
        }) == noErr else { return nil }

        var sample: CMSampleBuffer?
        var size = payload.count
        guard CMSampleBufferCreateReady(
            allocator: kCFAllocatorDefault, dataBuffer: block, formatDescription: format,
            sampleCount: 1, sampleTimingEntryCount: 0, sampleTimingArray: nil,
            sampleSizeEntryCount: 1, sampleSizeArray: &size, sampleBufferOut: &sample) == noErr
        else { return nil }
        return sample
    }
}
