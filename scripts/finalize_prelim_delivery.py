"""Validate and package separate competition materials and private team runtime."""

import argparse
import hashlib
import json
import shutil
import zipfile
from datetime import UTC, datetime
from pathlib import Path


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def archive(directory, target):
    if target.exists():
        raise FileExistsError(target)
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as output:
        for path in sorted(directory.rglob("*")):
            if path.is_file():
                output.write(path, str(Path(directory.name) / path.relative_to(directory)))
    with zipfile.ZipFile(target) as output:
        if output.testzip() is not None:
            raise ValueError("ZIP CRC verification failed")
        for path in directory.rglob("*"):
            if path.is_file():
                name = str(Path(directory.name) / path.relative_to(directory))
                if hashlib.sha256(output.read(name)).hexdigest() != digest(path):
                    raise ValueError(f"ZIP content mismatch: {name}")
    target.with_suffix(".sha256").write_text(digest(target) + "  " + target.name + "\n")
    return {"file": target.name, "bytes": target.stat().st_size, "sha256": digest(target)}


def finalize(root):
    release = root / "release"
    pack = release / "zhidu-prelim-final-20261019"
    artifacts = root / "output/prelim-final-20261018/materials"
    video = root / "output/prelim-final-20261018/video/知盾-初赛操作演示.mp4"
    assert json.loads((pack / "validation/smoke.json").read_text())["status"] == "passed"
    tests = json.loads((pack / "validation/material-validation.json").read_text())
    assert tests["python_failed"] == 0 and tests["python_passed"] == 1019
    assert tests["node_passed"] == 56
    media = json.loads(video.with_suffix(".json").read_text())
    assert media["represented_capture_count"] == media["capture_count"]
    assert media["media"]["duration_seconds"] > 60
    assert media["media"]["tracks"][0]["width"] == 1920
    official = release / "知盾-初赛正式材料-20261019"
    official.mkdir(exist_ok=False)
    for name in ("知盾初赛技术报告.docx", "知盾初赛技术报告.pdf", "知盾初赛技术讲解.pdf"):
        shutil.copyfile(artifacts / name, official / name)
    shutil.copyfile(video, official / "知盾初赛操作演示.mp4")
    if len(list(official.iterdir())) != 4:
        raise ValueError("Competition material set must contain exactly the four deliverables")
    internal = release / "团队编辑源-20261019"
    internal.mkdir(exist_ok=False)
    shutil.copyfile(
        artifacts / "internal/知盾初赛技术讲解.pptx", internal / "知盾初赛技术讲解.pptx"
    )
    for cache in (".pytest_cache", ".ruff_cache", "build"):
        path = pack / cache
        if path.exists():
            shutil.rmtree(path)
    for path in list(pack.rglob("__pycache__")):
        shutil.rmtree(path)
    files = sorted(path for path in pack.rglob("*") if path.is_file())
    for path in files:
        relative = path.relative_to(pack)
        assert not path.is_symlink()
        assert not any(p in {".env", ".venv", ".git", "archives"} for p in relative.parts)
    write_json(
        pack / "MANIFEST.json",
        {
            "format": "zhidu-initial-runtime-v1",
            "created_at": datetime.now(UTC).isoformat(),
            "competition_submission": False,
            "files": {
                str(path.relative_to(pack)): digest(path)
                for path in files
                if path.name != "MANIFEST.json"
            },
        },
    )
    result = {
        "date": "2026-10-19",
        "implementation_baseline": "2026-10-18",
        "official_materials": archive(official, release / "知盾-初赛正式材料-20261019.zip"),
        "team_runtime_not_for_separate_competition_submission": archive(
            pack, release / "知盾-团队运行工程-20261019.zip"
        ),
        "official_files": [
            {"file": p.name, "sha256": digest(p)} for p in sorted(official.iterdir())
        ],
        "private_configuration_included": False,
        "cloud_model_calls": 0,
    }
    write_json(release / "初赛交付校验-20261019.json", result)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    finalize(args.root.resolve())
