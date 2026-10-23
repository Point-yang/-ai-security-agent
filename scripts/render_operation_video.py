#!/usr/bin/env python3
"""Encode a browser interaction capture using its genuine capture timestamps.

frames.json: [{"file": "frames/000001.jpg", "at_ms": 0}, ...]
events.json: [{"at_ms": 0, "title": "章节", "caption": "操作说明",
               "badge": "实机操作", "narration": "可选旁白"}, ...]

Each frame persists until the next captured frame. This is a periodic browser
frame capture, not a claim of native OS/60 fps screen recording. Information bars
are outside the unchanged screenshot. --narrate never extends the real timeline.
Optional --trim-idle-gaps-ms removes only long intervals with no captured frames;
--keep-idle-ms controls the hold retained before each cut. Raw timestamps remain
in the metadata, and edited output is explicitly labelled as a cut operation video.
Requires Pillow and macOS system Swift/AVFoundation; no ffmpeg is needed.
"""

from __future__ import annotations

import argparse
import bisect
import hashlib
import json
import math
import statistics
import subprocess
import wave
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

# The native encoder source is included below, keeping this script independent
# from any previous rendered video's temporary helper/cache directory.
SWIFT_SOURCE = r"""

import Foundation
import AVFoundation
import AppKit

struct Segment: Decodable { let image: String; let frames: Int }
struct Manifest: Decodable {
    let width: Int; let height: Int; let fps: Int
    let segments: [Segment]; let audio: String; let output: String
}
func fail(_ text: String) -> Never {
    FileHandle.standardError.write(Data((text + "\n").utf8)); exit(1)
}
func fourcc(_ value: FourCharCode) -> String {
    let bytes: [UInt8] = [UInt8((value >> 24) & 255), UInt8((value >> 16) & 255),
                          UInt8((value >> 8) & 255), UInt8(value & 255)]
    return String(bytes: bytes, encoding: .ascii) ?? String(value)
}
func probe(_ path: String) throws {
    let asset = AVURLAsset(url: URL(fileURLWithPath: path))
    var result: [String: Any] = ["duration_seconds": CMTimeGetSeconds(asset.duration)]
    var tracks: [[String: Any]] = []
    for track in asset.tracks {
        var info: [String: Any] = ["media_type": track.mediaType.rawValue,
            "duration_seconds": CMTimeGetSeconds(track.timeRange.duration)]
        if let desc = track.formatDescriptions.first {
            let format = desc as! CMFormatDescription
            info["codec"] = fourcc(CMFormatDescriptionGetMediaSubType(format))
        }
        if track.mediaType == .video {
            info["width"] = track.naturalSize.width
            info["height"] = track.naturalSize.height
            info["fps"] = track.nominalFrameRate
            let reader = try AVAssetReader(asset: asset)
            let output = AVAssetReaderTrackOutput(track: track, outputSettings:
                [kCVPixelBufferPixelFormatTypeKey as String:
                    kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange])
            reader.add(output)
            if reader.startReading(), let sample = output.copyNextSampleBuffer(),
               let image = CMSampleBufferGetImageBuffer(sample) {
                info["decoded_pixel_format"] = fourcc(CVPixelBufferGetPixelFormatType(image))
                info["chroma_subsampling"] = "4:2:0 (8-bit)"
                reader.cancelReading()
            }
        } else if track.mediaType == .audio,
                  let desc = track.formatDescriptions.first {
            let format = desc as! CMAudioFormatDescription
            if let audio = CMAudioFormatDescriptionGetStreamBasicDescription(format) {
                info["sample_rate"] = audio.pointee.mSampleRate
                info["channels"] = audio.pointee.mChannelsPerFrame
            }
        }
        tracks.append(info)
    }
    result["tracks"] = tracks
    let data = try JSONSerialization.data(withJSONObject: result, options: [.prettyPrinted, .sortedKeys])
    print(String(data: data, encoding: .utf8)!)
}
func extract(_ path: String, _ seconds: Double, _ output: String) throws {
    let asset = AVURLAsset(url: URL(fileURLWithPath: path))
    let generator = AVAssetImageGenerator(asset: asset)
    generator.appliesPreferredTrackTransform = true
    let cg = try generator.copyCGImage(at: CMTime(seconds: seconds, preferredTimescale: 600), actualTime: nil)
    let bitmap = NSBitmapImageRep(cgImage: cg)
    guard let data = bitmap.representation(using: .png, properties: [:]) else { fail("PNG conversion failed") }
    try data.write(to: URL(fileURLWithPath: output))
}
func pixels(_ path: String, _ width: Int, _ height: Int) -> CVPixelBuffer {
    guard let source = NSImage(contentsOfFile: path),
          let image = source.cgImage(forProposedRect: nil, context: nil, hints: nil)
    else { fail("Cannot load frame: \(path)") }
    var buffer: CVPixelBuffer?
    let status = CVPixelBufferCreate(kCFAllocatorDefault, width, height,
        kCVPixelFormatType_32ARGB,
        [kCVPixelBufferCGImageCompatibilityKey: true,
         kCVPixelBufferCGBitmapContextCompatibilityKey: true] as CFDictionary, &buffer)
    guard status == kCVReturnSuccess, let pixel = buffer else { fail("Pixel allocation failed") }
    CVPixelBufferLockBaseAddress(pixel, [])
    guard let context = CGContext(data: CVPixelBufferGetBaseAddress(pixel), width: width,
        height: height, bitsPerComponent: 8, bytesPerRow: CVPixelBufferGetBytesPerRow(pixel),
        space: CGColorSpaceCreateDeviceRGB(), bitmapInfo: CGImageAlphaInfo.noneSkipFirst.rawValue)
    else { fail("Pixel context failed") }
    context.draw(image, in: CGRect(x: 0, y: 0, width: width, height: height))
    CVPixelBufferUnlockBaseAddress(pixel, [])
    return pixel
}
func render(_ path: String) throws {
    let manifest = try JSONDecoder().decode(Manifest.self, from: Data(contentsOf: URL(fileURLWithPath: path)))
    let url = URL(fileURLWithPath: manifest.output)
    try? FileManager.default.removeItem(at: url)
    let writer = try AVAssetWriter(outputURL: url, fileType: .mp4)
    let video = AVAssetWriterInput(mediaType: .video, outputSettings: [
        AVVideoCodecKey: AVVideoCodecType.h264,
        AVVideoWidthKey: manifest.width, AVVideoHeightKey: manifest.height,
        AVVideoCompressionPropertiesKey: [
            AVVideoAverageBitRateKey: 7_000_000,
            AVVideoProfileLevelKey: AVVideoProfileLevelH264HighAutoLevel,
            AVVideoMaxKeyFrameIntervalKey: manifest.fps * 2],
        AVVideoColorPropertiesKey: [
            AVVideoColorPrimariesKey: AVVideoColorPrimaries_ITU_R_709_2,
            AVVideoTransferFunctionKey: AVVideoTransferFunction_ITU_R_709_2,
            AVVideoYCbCrMatrixKey: AVVideoYCbCrMatrix_ITU_R_709_2]])
    video.expectsMediaDataInRealTime = false
    let adaptor = AVAssetWriterInputPixelBufferAdaptor(assetWriterInput: video,
        sourcePixelBufferAttributes: [kCVPixelBufferPixelFormatTypeKey as String: kCVPixelFormatType_32ARGB,
            kCVPixelBufferWidthKey as String: manifest.width,
            kCVPixelBufferHeightKey as String: manifest.height])
    guard writer.canAdd(video) else { fail("Cannot add H.264 input") }
    writer.add(video)
    let audioAsset = AVURLAsset(url: URL(fileURLWithPath: manifest.audio))
    guard let sourceAudio = audioAsset.tracks(withMediaType: .audio).first else { fail("No narration audio") }
    let reader = try AVAssetReader(asset: audioAsset)
    let audioReader = AVAssetReaderTrackOutput(track: sourceAudio, outputSettings: [
        AVFormatIDKey: kAudioFormatLinearPCM, AVLinearPCMBitDepthKey: 16,
        AVLinearPCMIsFloatKey: false, AVLinearPCMIsBigEndianKey: false,
        AVLinearPCMIsNonInterleaved: false])
    reader.add(audioReader)
    let audio = AVAssetWriterInput(mediaType: .audio, outputSettings: [
        AVFormatIDKey: kAudioFormatMPEG4AAC, AVSampleRateKey: 48000,
        AVNumberOfChannelsKey: 1, AVEncoderBitRateKey: 128000])
    audio.expectsMediaDataInRealTime = false
    guard writer.canAdd(audio) else { fail("Cannot add AAC input") }
    writer.add(audio)
    guard writer.startWriting(), reader.startReading() else {
        fail("Cannot start encoder: \(String(describing: writer.error)) \(String(describing: reader.error))")
    }
    writer.startSession(atSourceTime: .zero)
    let totalFrames = manifest.segments.reduce(0) { $0 + $1.frames }
    var frame = 0
    var segmentIndex = 0
    var segmentEnd = manifest.segments[0].frames
    var pixel = autoreleasepool { pixels(manifest.segments[0].image, manifest.width, manifest.height) }
    var videoDone = false
    var audioDone = false
    while !videoDone || !audioDone {
        var progressed = false
        if !videoDone && video.isReadyForMoreMediaData {
            if frame >= totalFrames {
                video.markAsFinished(); videoDone = true
            } else {
                if frame >= segmentEnd {
                    segmentIndex += 1
                    segmentEnd += manifest.segments[segmentIndex].frames
                    pixel = autoreleasepool { pixels(manifest.segments[segmentIndex].image, manifest.width, manifest.height) }
                }
                let ok = autoreleasepool {
                    adaptor.append(pixel, withPresentationTime:
                        CMTime(value: Int64(frame), timescale: Int32(manifest.fps)))
                }
                if !ok { fail("Video append failed: \(String(describing: writer.error))") }
                frame += 1
            }
            progressed = true
        }
        if !audioDone && audio.isReadyForMoreMediaData {
            if let sample = audioReader.copyNextSampleBuffer() {
                if !audio.append(sample) { fail("Audio append failed: \(String(describing: writer.error))") }
            } else {
                guard reader.status == .completed else {
                    fail("Audio reading failed: \(String(describing: reader.error))")
                }
                audio.markAsFinished(); audioDone = true
            }
            progressed = true
        }
        if writer.status == .failed { fail("Encoding failed: \(String(describing: writer.error))") }
        if !progressed { Thread.sleep(forTimeInterval: 0.002) }
    }
    let wait = DispatchSemaphore(value: 0)
    writer.finishWriting { wait.signal() }
    wait.wait()
    guard writer.status == .completed else { fail("Finishing failed: \(String(describing: writer.error))") }
}
do {
    let args = CommandLine.arguments
    if args.count >= 3 && args[1] == "probe" { try probe(args[2]) }
    else if args.count == 5 && args[1] == "extract" {
        try extract(args[2], Double(args[3])!, args[4])
    } else if args.count == 3 && args[1] == "render" { try render(args[2]) }
    else { fail("Usage: media-helper render manifest.json | probe movie.mp4 | extract movie.mp4 seconds frame.png") }
} catch { fail(String(describing: error)) }
"""


def run(command: list[str]) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(command, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as error:
        details = (error.stderr or error.stdout or str(error)).strip()
        raise RuntimeError(f"Media command failed: {command[0]}\n{details}") from error


def load_records(path: Path, key: str) -> list[dict]:
    data = json.loads(path.read_text())
    records = data if isinstance(data, list) else data[key]
    if not records:
        raise ValueError(f"No records in {path}")
    previous = -1
    for record in records:
        timestamp = record.get("at_ms")
        if not isinstance(timestamp, (int, float)) or timestamp < 0:
            raise ValueError(f"Invalid at_ms in {path}: {timestamp}")
        if timestamp <= previous:
            raise ValueError(f"Timestamps must strictly increase in {path}")
        previous = timestamp
    if records[0]["at_ms"] != 0:
        raise ValueError(f"The first timestamp must be zero in {path}")
    return records


def face(size: int) -> ImageFont.FreeTypeFont:
    for path in ["/System/Library/Fonts/STHeiti Medium.ttc", "/System/Library/Fonts/PingFang.ttc"]:
        if Path(path).is_file():
            return ImageFont.truetype(path, size)
    raise RuntimeError("A system Chinese font is required")


def wrap(
    text: str, draw: ImageDraw.ImageDraw, font: ImageFont.FreeTypeFont, width: int
) -> list[str]:
    lines = []
    line = ""
    for character in text:
        if character == "\n":
            lines.append(line)
            line = ""
        elif line and draw.textlength(line + character, font=font) > width:
            lines.append(line)
            line = character
        else:
            line += character
    if line:
        lines.append(line)
    return lines


def add_information_bars(
    source: Path,
    target: Path,
    event: dict,
    title: str,
    width: int,
    height: int,
    capture_index: int,
    total_captures: int,
    at_ms: float,
    end_ms: float,
    pointer: list | None = None,
    edited: bool = False,
) -> None:
    canvas = Image.new("RGB", (width, height), "#08111f")
    draw = ImageDraw.Draw(canvas)
    scale = width / 1920
    heading_face, badge_face, caption_face = (
        face(round(36 * scale)),
        face(round(22 * scale)),
        face(round(30 * scale)),
    )
    badge = event.get("badge", "实机操作")
    accent = "#facc80" if "历史" in badge else "#72e3d0"
    if "隔离" in badge or "虚构" in badge:
        accent = "#d4beff"
    draw.text(
        (round(28 * scale), round(13 * scale)), title, font=face(round(19 * scale)), fill="#8fa5be"
    )
    badge_width = draw.textlength(badge, font=badge_face) + 28 * scale
    badge_x = width - badge_width - 28 * scale
    heading = event.get("title", "操作演示")
    while draw.textlength(heading, font=heading_face) > badge_x - 52 * scale:
        heading_face = face(heading_face.size - 1)
        if heading_face.size < 20 * scale:
            raise ValueError(f"Event title is too long: {heading}")
    draw.text((round(28 * scale), round(42 * scale)), heading, font=heading_face, fill="#eff6ff")
    draw.rounded_rectangle(
        (round(badge_x), round(38 * scale), width - round(28 * scale), round(80 * scale)),
        radius=round(9 * scale),
        fill="#112538",
        outline=accent,
        width=max(1, round(scale)),
    )
    draw.text((round(badge_x + 14 * scale), round(49 * scale)), badge, font=badge_face, fill=accent)
    screenshot = Image.open(source).convert("RGB")
    original_width, original_height = screenshot.size
    box_top, box_bottom = round(96 * scale), height - round(160 * scale)
    box_left, box_right = round(20 * scale), width - round(20 * scale)
    screenshot.thumbnail((box_right - box_left, box_bottom - box_top), Image.Resampling.LANCZOS)
    screenshot_x = box_left + (box_right - box_left - screenshot.width) // 2
    screenshot_y = box_top + (box_bottom - box_top - screenshot.height) // 2
    canvas.paste(screenshot, (screenshot_x, screenshot_y))
    if pointer is not None:
        x, y = pointer
        if not (0 <= x <= original_width and 0 <= y <= original_height):
            raise ValueError(f"Pointer annotation is outside screenshot: {pointer}")
        x = screenshot_x + x / original_width * screenshot.width
        y = screenshot_y + y / original_height * screenshot.height
        radius = 18 * scale
        draw.ellipse(
            (x - radius, y - radius, x + radius, y + radius),
            outline="#ffd580",
            width=max(2, round(4 * scale)),
        )
        draw.ellipse((x - 3 * scale, y - 3 * scale, x + 3 * scale, y + 3 * scale), fill="#ffd580")
    caption = event.get("caption", "")
    lines = wrap(caption, draw, caption_face, width - round(100 * scale))
    if len(lines) > 2:
        caption_face = face(round(26 * scale))
        lines = wrap(caption, draw, caption_face, width - round(100 * scale))
    if len(lines) > 3:
        raise ValueError(f"Caption exceeds the outside information bar: {caption}")
    y = height - round(141 * scale)
    for line in lines:
        draw.text(
            ((width - draw.textlength(line, font=caption_face)) / 2, y),
            line,
            font=caption_face,
            fill="#eff6ff",
        )
        y += round(36 * scale)
    footer = "真实操作截帧 · 空档压缩剪辑" if edited else "浏览器连续交互帧 · 按真实时间戳编码"
    if pointer is not None:
        footer += " · 圆环为实际点击位置标注"
    draw.text(
        (round(28 * scale), height - round(28 * scale)),
        footer,
        font=face(round(17 * scale)),
        fill="#8399b3",
    )
    clock = f"{int(at_ms / 1000) // 60:02d}:{int(at_ms / 1000) % 60:02d} / {int(end_ms / 1000) // 60:02d}:{int(end_ms / 1000) % 60:02d}"
    label = f"{clock}   捕获帧 {capture_index + 1}/{total_captures}"
    label_face = face(round(17 * scale))
    draw.text(
        (width - 28 * scale - draw.textlength(label, font=label_face), height - round(28 * scale)),
        label,
        font=label_face,
        fill=accent,
    )
    canvas.save(target)


def srt_time(milliseconds: float) -> str:
    value = round(milliseconds)
    hours, value = divmod(value, 3600000)
    minutes, value = divmod(value, 60000)
    seconds, value = divmod(value, 1000)
    return f"{hours:02}:{minutes:02}:{seconds:02},{value:03}"


def edit_idle_gaps(
    frames: list[dict],
    events: list[dict],
    end_ms: float,
    threshold_ms: float | None,
    keep_ms: float,
) -> tuple[list[dict], list[dict], float, list[dict]]:
    """Map every timestamp through the same optional cuts in unobserved gaps.

    A deleted interval starts after keep_ms of the earlier captured frame and
    ends exactly at the next captured frame. Nothing within a captured sequence
    is sped up. Events in a removed interval collapse to that cut's boundary.
    """
    removed = []
    if threshold_ms is not None:
        if threshold_ms <= 0 or keep_ms <= 0 or keep_ms > threshold_ms:
            raise ValueError("Idle trimming requires 0 < keep-idle-ms <= trim-idle-gaps-ms")
        elapsed_removed = 0.0
        for previous, following in zip(frames, frames[1:], strict=False):
            gap = following["at_ms"] - previous["at_ms"]
            if gap > threshold_ms:
                start = previous["at_ms"] + keep_ms
                stop = following["at_ms"]
                duration = stop - start
                removed.append(
                    {
                        "raw_start_ms": start,
                        "raw_end_ms": stop,
                        "removed_ms": duration,
                        "edited_cut_ms": start - elapsed_removed,
                        "previous_capture_at_ms": previous["at_ms"],
                        "next_capture_at_ms": following["at_ms"],
                    }
                )
                elapsed_removed += duration

    def mapped(timestamp: float) -> float:
        deducted = sum(
            max(0, min(timestamp, interval["raw_end_ms"]) - interval["raw_start_ms"])
            for interval in removed
        )
        return timestamp - deducted

    mapped_frames = [
        {**item, "raw_at_ms": item["at_ms"], "at_ms": mapped(item["at_ms"])} for item in frames
    ]
    mapped_events = [
        {**item, "raw_at_ms": item["at_ms"], "at_ms": mapped(item["at_ms"])} for item in events
    ]
    return mapped_frames, mapped_events, mapped(end_ms), removed


def create_soundtrack(
    events: list[dict], end_ms: float, wav_path: Path, narrate: bool, voice: str, rate: int
) -> list[dict]:
    sample_rate = 48000
    samples = round(end_ms / 1000 * sample_rate)
    pcm = bytearray(samples * 2)
    records = []
    if narrate:
        for index, event in enumerate(events):
            text = event.get("narration", "")
            if not text:
                continue
            text_path = wav_path.parent / f"speech-{index + 1:02d}.txt"
            aiff_path = text_path.with_suffix(".aiff")
            voice_path = text_path.with_suffix(".wav")
            text_path.write_text(text)
            run(
                [
                    "/usr/bin/say",
                    "-v",
                    voice,
                    "-r",
                    str(rate),
                    "-o",
                    str(aiff_path),
                    "-f",
                    str(text_path),
                ]
            )
            run(
                [
                    "/usr/bin/afconvert",
                    "-f",
                    "WAVE",
                    "-d",
                    "LEI16@48000",
                    "-c",
                    "1",
                    str(aiff_path),
                    str(voice_path),
                ]
            )
            with wave.open(str(voice_path), "rb") as audio:
                if (audio.getnchannels(), audio.getsampwidth(), audio.getframerate()) != (
                    1,
                    2,
                    sample_rate,
                ):
                    raise ValueError("Unexpected speech format")
                speech = audio.readframes(audio.getnframes())
            start_ms = event["at_ms"] + 350
            stop_ms = events[index + 1]["at_ms"] if index + 1 < len(events) else end_ms
            speech_ms = len(speech) / 2 / sample_rate * 1000
            if start_ms + speech_ms + 150 > stop_ms:
                raise ValueError(
                    f"Narration {index + 1} ({speech_ms / 1000:.1f}s) exceeds its real capture window. Shorten narration or omit --narrate."
                )
            start = round(start_ms / 1000 * sample_rate) * 2
            pcm[start : start + len(speech)] = speech
            records.append(
                {"event": index + 1, "start_ms": start_ms, "speech_ms": round(speech_ms, 2)}
            )
    with wave.open(str(wav_path), "wb") as output:
        output.setnchannels(1)
        output.setsampwidth(2)
        output.setframerate(sample_rate)
        output.writeframes(pcm)
    return records


def render(args: argparse.Namespace) -> dict:
    raw_frames = load_records(args.frames, "frames")
    raw_events = load_records(args.events, "events")
    raw_end_ms = args.end_ms if args.end_ms is not None else raw_frames[-1]["at_ms"] + 1000
    if raw_end_ms <= raw_frames[-1]["at_ms"] or raw_events[-1]["at_ms"] >= raw_end_ms:
        raise ValueError("end-ms must follow the final capture and event")
    frames, events, end_ms, removed = edit_idle_gaps(
        raw_frames, raw_events, raw_end_ms, args.trim_idle_gaps_ms, args.keep_idle_ms
    )
    edited = bool(removed)
    total_frames = math.ceil(end_ms / 1000 * args.fps)
    encoded_ms = total_frames / args.fps * 1000
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    work = output.parent / (output.stem + "-media")
    work.mkdir(exist_ok=True)
    source_paths, hashes = [], []
    for frame in frames:
        source = Path(frame["file"])
        if not source.is_absolute():
            source = args.frames.parent / source
        source = source.resolve()
        if not source.is_file():
            raise FileNotFoundError(source)
        source_paths.append(source)
        hashes.append(hashlib.sha256(source.read_bytes()).hexdigest())
    frame_ms = [frame["at_ms"] for frame in frames]
    event_ms = [event["at_ms"] for event in events]
    pointer_ms = [
        max(0, event["at_ms"] - 800) for event in events if event.get("pointer") is not None
    ]
    boundaries = sorted(
        {0, total_frames}
        | {round(value / 1000 * args.fps) for value in frame_ms + event_ms + pointer_ms}
    )
    segments = []
    used_indices = set()
    for segment_index, (start_frame, stop_frame) in enumerate(
        zip(boundaries, boundaries[1:], strict=False)
    ):
        timestamp = start_frame / args.fps * 1000
        # Boundary rounding may land a fraction before its source capture; use
        # the nearest half-frame tolerance when selecting the captured frame.
        source_index = bisect.bisect_right(frame_ms, timestamp + 500 / args.fps) - 1
        event_index = bisect.bisect_right(event_ms, timestamp + 500 / args.fps) - 1
        pointers = [
            event["pointer"]
            for event in events
            if event.get("pointer") is not None
            and max(0, event["at_ms"] - 800) <= timestamp < event["at_ms"]
        ]
        used_indices.add(source_index)
        composed_path = work / f"frame-{segment_index:06d}.png"
        add_information_bars(
            source_paths[source_index],
            composed_path,
            events[event_index],
            args.title,
            args.width,
            args.height,
            source_index,
            len(frames),
            timestamp,
            encoded_ms,
            pointers[-1] if pointers else None,
            edited,
        )
        segments.append({"image": str(composed_path), "frames": stop_frame - start_frame})
        if segment_index % 100 == 0:
            print(
                f"Composited {segment_index + 1}/{len(boundaries) - 1} timeline segments",
                flush=True,
            )
    soundtrack = work / "soundtrack.wav"
    voice_records = create_soundtrack(
        events, encoded_ms, soundtrack, args.narrate, args.voice, args.rate
    )
    subtitles = []
    zero_duration_events = []
    for index, event in enumerate(events):
        stop = events[index + 1]["at_ms"] if index + 1 < len(events) else encoded_ms
        if stop <= event["at_ms"]:
            zero_duration_events.append(index + 1)
            continue
        subtitles.append(
            f"{len(subtitles) + 1}\n{srt_time(event['at_ms'])} --> {srt_time(stop)}\n{event.get('title', '')}\n{event.get('caption', '')}\n"
        )
    output.with_suffix(".srt").write_text("\n".join(subtitles))
    raw_ms = [frame["at_ms"] for frame in raw_frames]
    intervals = [b - a for a, b in zip(raw_ms, raw_ms[1:], strict=False)]
    metadata = {
        "kind": "edited_real_ui_operation_capture"
        if edited
        else "periodic-browser-interaction-capture",
        "native_os_screen_recording": False,
        "continuous_screen_recording": False,
        "source_content_modified": False,
        "click_location_annotations": any(event.get("pointer") is not None for event in events),
        "timeline_extended_for_narration": False,
        "capture_count": len(frames),
        "represented_capture_count": len(used_indices),
        "distinct_captured_images_sha256": len(set(hashes)),
        "capture_median_interval_ms": statistics.median(intervals) if intervals else None,
        "capture_max_interval_ms": max(intervals) if intervals else None,
        "long_capture_gaps_over_2000ms": [
            {"after_capture": i + 1, "gap_ms": gap} for i, gap in enumerate(intervals) if gap > 2000
        ],
        "requested_capture_end_ms": raw_end_ms,
        "raw_duration_ms": raw_end_ms,
        "edited_duration_ms": end_ms,
        "idle_gap_trimming": {
            "enabled": args.trim_idle_gaps_ms is not None,
            "threshold_ms": args.trim_idle_gaps_ms,
            "keep_ms": args.keep_idle_ms,
            "removed_total_ms": raw_end_ms - end_ms,
        },
        "removed_idle_intervals": removed,
        "zero_duration_events_after_trimming": zero_duration_events,
        "encoded_duration_ms": encoded_ms,
        "container_fps": args.fps,
        "narration": {
            "enabled": args.narrate,
            "voice": args.voice if args.narrate else None,
            "segments": voice_records,
        },
        "events": events,
        "sources": [
            {
                "file": str(path),
                "at_ms": frame["at_ms"],
                "raw_at_ms": frame["raw_at_ms"],
                "sha256": digest,
            }
            for path, frame, digest in zip(source_paths, frames, hashes, strict=True)
        ],
    }
    manifest = work / "encode-manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "width": args.width,
                "height": args.height,
                "fps": args.fps,
                "segments": segments,
                "audio": str(soundtrack),
                "output": str(output),
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    # The poster represents the first genuine captured interaction frame.
    shutil_source = Path(segments[0]["image"])
    output.with_suffix(".poster.png").write_bytes(shutil_source.read_bytes())
    if not args.prepare_only:
        swift_path, helper = work / "media-helper.swift", work / "media-helper"
        swift_path.write_text(SWIFT_SOURCE)
        cache = work / "swift-cache"
        cache.mkdir(exist_ok=True)
        print("Compiling native AVFoundation encoder...", flush=True)
        run(
            [
                "/usr/bin/swiftc",
                "-O",
                "-module-cache-path",
                str(cache),
                str(swift_path),
                "-o",
                str(helper),
            ]
        )
        print("Encoding timestamped interaction video...", flush=True)
        run([str(helper), "render", str(manifest)])
        metadata["media"] = json.loads(run([str(helper), "probe", str(output)]).stdout)
        metadata["output_bytes"] = output.stat().st_size
        metadata["helper"] = str(helper)
        for index, point in enumerate(
            [0.0, encoded_ms / 4000, encoded_ms / 2000, encoded_ms * 0.75 / 1000], 1
        ):
            run(
                [
                    str(helper),
                    "extract",
                    str(output),
                    str(point),
                    str(output.parent / f"qa-{index:02d}.png"),
                ]
            )
    output.with_suffix(".json").write_text(json.dumps(metadata, ensure_ascii=False, indent=2))
    return metadata


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("frames", type=Path)
    parser.add_argument("events", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--end-ms", type=float)
    parser.add_argument(
        "--trim-idle-gaps-ms",
        type=float,
        help="Optionally shorten gaps without captured frames exceeding this duration",
    )
    parser.add_argument(
        "--keep-idle-ms",
        type=float,
        default=700,
        help="Hold retained before each idle gap cut (default: 700ms)",
    )
    parser.add_argument("--title", default="知盾 · 初赛操作演示")
    parser.add_argument("--width", type=int, default=1920)
    parser.add_argument("--height", type=int, default=1080)
    parser.add_argument("--fps", type=int, default=12)
    parser.add_argument("--narrate", action="store_true")
    parser.add_argument("--voice", default="Tingting")
    parser.add_argument("--rate", type=int, default=185)
    parser.add_argument("--prepare-only", action="store_true")
    args = parser.parse_args()
    result = render(args)
    print(
        json.dumps(
            {
                key: result[key]
                for key in [
                    "capture_count",
                    "represented_capture_count",
                    "distinct_captured_images_sha256",
                    "encoded_duration_ms",
                ]
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
