from __future__ import annotations

import argparse
import hashlib
import json
import tarfile
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DIST = ROOT / "mobile" / "web" / "dist"
DEFAULT_NGINX = ROOT / "deploy" / "web" / "nginx" / "pqmsg-web.conf"
DEFAULT_OUTPUT = ROOT / "dist" / "web-release"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Package the built PQmsg web shell into a versioned VPS deployment bundle."
    )
    parser.add_argument("--dist-dir", type=Path, default=DEFAULT_DIST)
    parser.add_argument("--nginx-config", type=Path, default=DEFAULT_NGINX)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--release-id",
        default=datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S"),
        help="Release identifier used in bundle filenames and metadata.",
    )
    return parser.parse_args()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def main() -> None:
    args = parse_args()
    dist_dir = args.dist_dir.resolve()
    nginx_config = args.nginx_config.resolve()
    output_dir = args.output_dir.resolve()
    release_id = args.release_id.strip()

    require(release_id, "release id must not be empty")
    require(dist_dir.is_dir(), f"dist directory does not exist: {dist_dir}")
    require((dist_dir / "index.html").is_file(), f"dist directory is missing index.html: {dist_dir}")
    require(nginx_config.is_file(), f"nginx config does not exist: {nginx_config}")

    output_dir.mkdir(parents=True, exist_ok=True)
    bundle_name = f"pqmsg-web-{release_id}"
    tarball_path = output_dir / f"{bundle_name}.tar.gz"
    manifest_path = output_dir / f"{bundle_name}.manifest.json"

    site_files = []
    for path in sorted(dist_dir.rglob("*")):
        if path.is_file():
            rel = path.relative_to(dist_dir).as_posix()
            site_files.append(
                {
                    "path": f"site/{rel}",
                    "size_bytes": path.stat().st_size,
                    "sha256": sha256_file(path),
                }
            )

    nginx_entry = {
        "path": "nginx/pqmsg-web.conf",
        "size_bytes": nginx_config.stat().st_size,
        "sha256": sha256_file(nginx_config),
    }

    manifest = {
        "release_id": release_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "bundle_name": bundle_name,
        "bundle_path": str(tarball_path),
        "source_dist_dir": str(dist_dir),
        "files": site_files + [nginx_entry],
    }

    manifest_bytes = json.dumps(manifest, indent=2).encode("utf-8")
    version_bytes = f"{release_id}\n".encode("utf-8")

    with tarfile.open(tarball_path, "w:gz") as archive:
        for path in sorted(dist_dir.rglob("*")):
            if path.is_file():
                archive.add(path, arcname=f"{bundle_name}/site/{path.relative_to(dist_dir).as_posix()}")
        archive.add(nginx_config, arcname=f"{bundle_name}/nginx/pqmsg-web.conf")

        manifest_info = tarfile.TarInfo(name=f"{bundle_name}/manifest.json")
        manifest_info.size = len(manifest_bytes)
        archive.addfile(manifest_info, io.BytesIO(manifest_bytes))

        version_info = tarfile.TarInfo(name=f"{bundle_name}/VERSION")
        version_info.size = len(version_bytes)
        archive.addfile(version_info, io.BytesIO(version_bytes))

    manifest_path.write_bytes(manifest_bytes)
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    import io

    main()
