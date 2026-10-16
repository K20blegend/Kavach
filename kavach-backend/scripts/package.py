"""Build a source-only handoff archive from an explicit list of project paths."""

import hashlib
import tomllib
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
ROOT_FILES = (
    "START_HERE.md",
    "README.md",
    "pyproject.toml",
    "requirements.lock.txt",
    ".env.example",
    ".gitignore",
    ".dockerignore",
    "Dockerfile",
    "compose.yaml",
)
SOURCE_DIRECTORIES = ("app", "tests", "scripts", ".github")
EXCLUDED_PARTS = {"__pycache__", ".pytest_cache", ".ruff_cache", ".env", ".data", ".venv", "memory"}
EXCLUDED_SUFFIXES = {".pyc", ".pyo", ".db", ".sqlite", ".sqlite3", ".zip"}
PREFIX = "kavach-backend"


def project_files() -> list[Path]:
    files = []
    for filename in ROOT_FILES:
        path = ROOT / filename
        if not path.is_file():
            raise FileNotFoundError(f"Required project file is missing: {filename}")
        files.append(path)
    for dirname in SOURCE_DIRECTORIES:
        directory = ROOT / dirname
        if not directory.is_dir():
            raise FileNotFoundError(f"Required project directory is missing: {dirname}")
        for path in directory.rglob("*"):
            relative = path.relative_to(ROOT)
            if any(part in EXCLUDED_PARTS for part in relative.parts):
                continue
            if path.is_symlink():
                raise ValueError(f"Symlinks cannot be included: {relative.as_posix()}")
            if path.is_file() and path.suffix.lower() not in EXCLUDED_SUFFIXES:
                files.append(path)
    for path in files:
        if path.is_symlink() or not path.resolve().is_relative_to(ROOT):
            raise ValueError("All packaged files must be inside the project")
    return sorted(files, key=lambda path: path.relative_to(ROOT).as_posix())


def add_file(archive: ZipFile, name: str, content: bytes):
    info = ZipInfo(f"{PREFIX}/{name}", date_time=(2026, 1, 1, 0, 0, 0))
    info.compress_type = ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = 0o100644 << 16
    archive.writestr(info, content, compresslevel=9)


def main():
    version = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    destination = ROOT / "dist" / f"Kavach-Backend-v{version}.zip"
    destination.parent.mkdir(exist_ok=True)
    files = project_files()
    manifest = []
    # Exclusive creation preserves any existing handoff archive.
    with ZipFile(destination, mode="x", compression=ZIP_DEFLATED) as archive:
        for path in files:
            relative = path.relative_to(ROOT).as_posix()
            content = path.read_bytes()
            manifest.append(f"{hashlib.sha256(content).hexdigest()}  {relative}")
            add_file(archive, relative, content)
        add_file(archive, "FILE_MANIFEST.sha256", ("\n".join(manifest) + "\n").encode())
    with ZipFile(destination) as archive:
        damaged = archive.testzip()
        if damaged:
            raise ValueError(f"Archive integrity check failed: {damaged}")
        assert len(archive.namelist()) == len(files) + 1
    print(f"Created {destination.name}: {len(files)} project files and a checksum manifest")
    print(f"Size: {destination.stat().st_size:,} bytes")


if __name__ == "__main__":
    main()
