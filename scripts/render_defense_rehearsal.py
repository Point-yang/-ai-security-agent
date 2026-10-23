#!/usr/bin/env python3
"""Render a narrated rehearsal from genuine browser screenshots on macOS.

Input: {"title": "...", "scenes": [{"image": "frames/01.jpg", "title": "...",
"narration": "...", "duration": 12, "badge": "实机页面", "crop": [x,y,w,h]}]}.
Uses Pillow, the system Chinese voice, and AVFoundation; it needs no ffmpeg.
The source screenshot is only resized/cropped, never reconstructed or edited.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import shutil
import subprocess
import wave
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

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
    var pixel = pixels(manifest.segments[0].image, manifest.width, manifest.height)
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
                    pixel = pixels(manifest.segments[segmentIndex].image, manifest.width, manifest.height)
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


def font(size: int) -> ImageFont.FreeTypeFont:
    candidates = [
        "/System/Library/Fonts/STHeiti Medium.ttc",
        "/System/Library/Fonts/PingFang.ttc",
        "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
    ]
    for candidate in candidates:
        if Path(candidate).is_file():
            return ImageFont.truetype(candidate, size)
    raise RuntimeError("No Chinese font is installed")


def wrap(
    text: str, draw: ImageDraw.ImageDraw, face: ImageFont.FreeTypeFont, width: int
) -> list[str]:
    lines: list[str] = []
    for paragraph in text.splitlines():
        line = ""
        for character in paragraph:
            if line and draw.textlength(line + character, font=face) > width:
                lines.append(line)
                line = character
            else:
                line += character
        if line:
            lines.append(line)
    return lines


def caption_chunks(text: str, max_chars: int = 76) -> list[str]:
    parts = re.findall(r"[^。！？；\n]+[。！？；]?", text)
    chunks: list[str] = []
    for part in parts:
        part = part.strip()
        if not part:
            continue
        if len(part) > max_chars:
            commas = re.findall(r"[^，、,]+[，、,]?", part)
            merged = ""
            for section in commas:
                if merged and len(merged + section) > max_chars:
                    chunks.append(merged)
                    merged = ""
                merged += section
            if merged:
                chunks.append(merged)
        else:
            chunks.append(part)
    return chunks or [""]


def draw_frame(
    source: Path,
    target: Path,
    scene: dict,
    subtitle: str,
    index: int,
    count: int,
    size: tuple[int, int],
    presentation_title: str,
) -> None:
    width, height = size
    scale = width / 1920
    image = Image.new("RGB", size, "#070f1d")
    draw = ImageDraw.Draw(image)
    accent = "#67e8d0"
    if "历史" in scene.get("badge", ""):
        accent = "#ffcf79"
    elif "隔离" in scene.get("badge", "") or "虚构" in scene.get("badge", ""):
        accent = "#cfb7ff"
    title_face, label_face, caption_face = (
        font(round(39 * scale)),
        font(round(21 * scale)),
        font(round(31 * scale)),
    )
    draw.text(
        (round(36 * scale), round(17 * scale)), presentation_title, font=label_face, fill="#849ab5"
    )
    badge = scene.get("badge", "实机页面")
    badge_width = draw.textlength(badge, font=label_face) + 28 * scale
    badge_left = width - badge_width - 36 * scale
    while draw.textlength(scene["title"], font=title_face) > badge_left - 64 * scale:
        title_face = font(title_face.size - 1)
        if title_face.size < 22 * scale:
            raise ValueError(f"Chapter title is too long: {scene['title']}")
    draw.text(
        (round(36 * scale), round(47 * scale)), scene["title"], font=title_face, fill="#f1f7ff"
    )
    draw.rounded_rectangle(
        (round(badge_left), round(42 * scale), width - round(36 * scale), round(82 * scale)),
        radius=round(10 * scale),
        fill="#142435",
        outline=accent,
        width=max(1, round(scale)),
    )
    draw.text(
        (round(badge_left + 14 * scale), round(51 * scale)), badge, font=label_face, fill=accent
    )

    source_image = Image.open(source).convert("RGB")
    if scene.get("crop"):
        x, y, crop_width, crop_height = scene["crop"]
        if (
            x < 0
            or y < 0
            or x + crop_width > source_image.width
            or y + crop_height > source_image.height
        ):
            raise ValueError(f"Crop is outside screenshot: {source}")
        source_image = source_image.crop((x, y, x + crop_width, y + crop_height))
    left, top = round(32 * scale), round(108 * scale)
    right, bottom = width - round(32 * scale), height - round(166 * scale)
    draw.rounded_rectangle(
        (left, top, right, bottom),
        radius=round(12 * scale),
        fill="#102034",
        outline="#30485d",
        width=2,
    )
    available = (right - left - round(8 * scale), bottom - top - round(8 * scale))
    fit_scale = min(available[0] / source_image.width, available[1] / source_image.height)
    source_image = source_image.resize(
        (round(source_image.width * fit_scale), round(source_image.height * fit_scale)),
        Image.Resampling.LANCZOS,
    )
    image.paste(
        source_image,
        (
            left + (right - left - source_image.width) // 2,
            top + (bottom - top - source_image.height) // 2,
        ),
    )
    lines = wrap(subtitle, draw, caption_face, width - round(120 * scale))
    if len(lines) > 2:
        caption_face = font(round(27 * scale))
        lines = wrap(subtitle, draw, caption_face, width - round(120 * scale))
    if len(lines) > 3:
        raise ValueError(f"Caption too long: {subtitle}")
    caption_top = height - round(143 * scale)
    for line in lines:
        text_width = draw.textlength(line, font=caption_face)
        draw.text(((width - text_width) / 2, caption_top), line, font=caption_face, fill="#edf5ff")
        caption_top += round(39 * scale)
    footer_y = height - round(31 * scale)
    draw.text(
        (round(36 * scale), footer_y),
        "真实页面截图剪辑 · 中文合成讲解",
        font=font(round(18 * scale)),
        fill="#7188a2",
    )
    progress = f"{index:02d} / {count:02d}"
    draw.text(
        (width - round(134 * scale), footer_y), progress, font=font(round(19 * scale)), fill=accent
    )
    image.save(target)


def timestamp(seconds: float) -> str:
    value = round(seconds * 1000)
    hours, value = divmod(value, 3600000)
    minutes, value = divmod(value, 60000)
    secs, millis = divmod(value, 1000)
    return f"{hours:02}:{minutes:02}:{secs:02},{millis:03}"


def render(args: argparse.Namespace) -> dict:
    document = json.loads(args.scenes.read_text())
    scenes = document if isinstance(document, list) else document["scenes"]
    title = (
        "知盾 · AI 安全知识情报系统"
        if isinstance(document, list)
        else document.get("title", "知盾 · AI 安全知识情报系统")
    )
    args.output = args.output.resolve()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    work = args.output.parent / (args.output.stem + "-media")
    work.mkdir(exist_ok=True)
    sample_rate = 48000
    fps = args.fps
    segments, metadata, srt = [], [], []
    timeline = 0.0
    combined_audio = work / "narration.wav"
    with wave.open(str(combined_audio), "wb") as soundtrack:
        soundtrack.setnchannels(1)
        soundtrack.setsampwidth(2)
        soundtrack.setframerate(sample_rate)
        for number, scene in enumerate(scenes, 1):
            source = Path(scene["image"])
            if not source.is_absolute():
                source = args.scenes.parent / source
            source = source.resolve()
            if not source.is_file():
                raise FileNotFoundError(source)
            narration = scene.get("narration", "")
            speech = b""
            if narration:
                text_path = work / f"{number:02d}-narration.txt"
                aiff_path = work / f"{number:02d}-voice.aiff"
                wav_path = work / f"{number:02d}-voice.wav"
                text_path.write_text(narration)
                run(
                    [
                        "/usr/bin/say",
                        "-v",
                        args.voice,
                        "-r",
                        str(args.rate),
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
                        str(wav_path),
                    ]
                )
                with wave.open(str(wav_path), "rb") as audio:
                    if (audio.getnchannels(), audio.getsampwidth(), audio.getframerate()) != (
                        1,
                        2,
                        sample_rate,
                    ):
                        raise ValueError("Unexpected speech audio format")
                    speech = audio.readframes(audio.getnframes())
            spoken_seconds = len(speech) / 2 / sample_rate
            lead = 0.6 if narration else 0.0
            duration = max(float(scene.get("duration", 0)), spoken_seconds + lead + 0.8, 3.0)
            scene_frames = math.ceil(duration * fps)
            duration = scene_frames / fps
            soundtrack.writeframes(b"\x00\x00" * round(lead * sample_rate))
            soundtrack.writeframes(speech)
            tail_samples = (
                round(duration * sample_rate) - round(lead * sample_rate) - len(speech) // 2
            )
            soundtrack.writeframes(b"\x00\x00" * tail_samples)
            captions = caption_chunks(scene.get("subtitle", narration))
            weights = [max(len(item), 1) for item in captions]
            allocated = 0
            scene_start = timeline
            for page, (caption, weight) in enumerate(zip(captions, weights, strict=True), 1):
                page_frames = (
                    scene_frames - allocated
                    if page == len(captions)
                    else max(1, round(scene_frames * weight / sum(weights)))
                )
                allocated += page_frames
                frame_path = work / f"{number:02d}-{page:02d}.png"
                draw_frame(
                    source,
                    frame_path,
                    scene,
                    caption,
                    number,
                    len(scenes),
                    (args.width, args.height),
                    title,
                )
                segments.append({"image": str(frame_path), "frames": page_frames})
                end = timeline + page_frames / fps
                srt.append(
                    f"{len(srt) + 1}\n{timestamp(timeline)} --> {timestamp(end)}\n{caption}\n"
                )
                timeline = end
            metadata.append(
                {
                    "index": number,
                    "title": scene["title"],
                    "image": str(source),
                    "crop": scene.get("crop"),
                    "badge": scene.get("badge", "实机页面"),
                    "start_seconds": round(scene_start, 3),
                    "duration_seconds": duration,
                    "speech_seconds": round(spoken_seconds, 3),
                    "subtitle_pages": len(captions),
                }
            )
            print(
                f"scene {number}/{len(scenes)}: {duration:.2f}s (speech {spoken_seconds:.2f}s) {scene['title']}",
                flush=True,
            )
    args.output.with_suffix(".srt").write_text("\n".join(srt))
    manifest_path = work / "encode-manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "width": args.width,
                "height": args.height,
                "fps": fps,
                "segments": segments,
                "audio": str(combined_audio),
                "output": str(args.output),
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    swift_path = work / "media-helper.swift"
    swift_path.write_text(SWIFT_SOURCE)
    helper = work / "media-helper"
    cache = work / "swift-cache"
    cache.mkdir(exist_ok=True)
    print("Compiling system AVFoundation encoder...", flush=True)
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
    print("Encoding H.264 and AAC...", flush=True)
    run([str(helper), "render", str(manifest_path)])
    probe = json.loads(run([str(helper), "probe", str(args.output)]).stdout)
    result = {
        "kind": "genuine-browser-screenshot-edit",
        "continuous_screen_recording": False,
        "voice": args.voice,
        "speech_rate": args.rate,
        "fps": fps,
        "scenes": metadata,
        "media": probe,
        "output_bytes": args.output.stat().st_size,
        "helper": str(helper),
        "srt": str(args.output.with_suffix(".srt")),
    }
    args.output.with_suffix(".json").write_text(json.dumps(result, ensure_ascii=False, indent=2))
    for point in [0.0, timeline / 3, timeline * 2 / 3, max(0, timeline - 1)]:
        frame_path = work / f"encoded-frame-{point:07.2f}.png"
        run([str(helper), "extract", str(args.output), str(point), str(frame_path)])
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenes", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--width", type=int, default=1920)
    parser.add_argument("--height", type=int, default=1080)
    parser.add_argument("--fps", type=int, default=24)
    parser.add_argument("--voice", default="Tingting")
    parser.add_argument("--rate", type=int, default=185)
    args = parser.parse_args()
    if not shutil.which("swiftc") or not Path("/usr/bin/say").is_file():
        raise RuntimeError("This renderer requires macOS system Swift and speech synthesis")
    result = render(args)
    print(
        json.dumps(
            {"output": str(args.output), "bytes": result["output_bytes"], "media": result["media"]},
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
