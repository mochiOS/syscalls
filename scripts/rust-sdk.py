#!/usr/bin/env python3
"""Package and install a host-independent mochiOS Rust target SDK (Python 3.11+)."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tempfile
import urllib.request
import zipfile

TARGET = "x86_64-unknown-mochios"
MAX_ARCHIVE_BYTES = 2 * 1024**3


def checksum(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def rustc(toolchain, *args):
    return subprocess.check_output(
        ["rustup", "run", toolchain, "rustc", *map(str, args)], text=True
    ).strip()


def compiler_info(toolchain):
    return dict(line.split(": ", 1) for line in rustc(toolchain, "-vV").splitlines() if ": " in line)


def license_files(paths):
    files = {}
    for index, path in enumerate(paths):
        if path.is_dir():
            notices = sorted(p for p in path.rglob('*') if p.is_file() and
                             p.name.upper().startswith(('LICENSE', 'COPYING', 'COPYRIGHT', 'NOTICE')))
            if not notices:
                raise ValueError(f"no license notices found: {path}")
            for notice in notices:
                files[f"licenses/{index}-{path.name}/{notice.relative_to(path).as_posix()}"] = notice
        else:
            files[f"licenses/{index}-{path.name}"] = path
    if not files:
        raise ValueError("license notices are required")
    return files


def pack(args):
    """Select exact dependencies from metadata, never mix cached std variants."""
    libraries = {}
    pending = [args.std_lib.resolve(), args.panic_lib.resolve()]
    while pending:
        lib = pending.pop()
        name = lib.stem[3:].rsplit("-", 1)[0]
        if name in libraries:
            if libraries[name] != lib:
                raise ValueError(f"conflicting versions of {name}")
            continue
        metadata = rustc(args.toolchain, "-Zls=root", lib)
        if f"triple {TARGET}\n" not in metadata:
            raise ValueError(f"wrong target: {lib}")
        libraries[name] = lib
        for dependency in re.findall(r"^\d+ (\w+-[0-9a-f]+) hash ", metadata, re.M):
            pending.append(lib.parent / f"lib{dependency}.rlib")
    if not {"std", "core", "alloc", "compiler_builtins", "panic_abort"} <= libraries.keys():
        raise ValueError("incomplete standard library")
    info = compiler_info(args.toolchain)
    manifest = {"format": 1, "target": TARGET, "toolchain": args.toolchain,
                "compiler_commit": info["commit-hash"]}
    files = {f"sysroot/lib/rustlib/{TARGET}/lib/{p.name}": p for p in libraries.values()}
    files[f"targets/{TARGET}.json"] = args.target
    files["lib/libgcc.a"] = args.libgcc
    for name in ("crt0.o", "libmochi_user_newlib_runtime.a", "linker.ld"):
        files[f"lib/{name}"] = args.c_sdk / "lib" / name
    for name in ("libc.a", "libm.a"):
        files[f"lib/{name}"] = args.c_sdk / "sysroot/lib" / name
    files["rust-sdk.py"] = Path(__file__)
    files.update(license_files(args.license))
    for path in files.values():
        if not path.is_file():
            raise ValueError(f"missing input: {path}")
        if path.suffix in ('.a', '.rlib', '.o') and os.fsencode(str(Path.home()) + '/') in path.read_bytes():
            raise ValueError(f"host home path embedded in {path}; rebuild with path remapping")
    # Exclusive creation avoids replacing an already published artifact.
    with zipfile.ZipFile(args.output, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("sdk.json", json.dumps(manifest, indent=2) + "\n")
        for name, path in sorted(files.items()):
            archive.write(path, name)
    print(f"{checksum(args.output)}  {args.output}")


def unpack(archive_path, destination):
    if destination.exists():
        raise ValueError(f"destination already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=destination.parent) as temporary:
        staging = Path(temporary) / "sdk"
        staging.mkdir()
        with zipfile.ZipFile(archive_path) as archive:
            seen = set()
            entries = archive.infolist()
            if sum(entry.file_size for entry in entries) > MAX_ARCHIVE_BYTES:
                raise ValueError("expanded archive too large")
            for entry in entries:
                path = PurePosixPath(entry.filename)
                folded = str(path).casefold()
                if (path.is_absolute() or ".." in path.parts or "\\" in entry.filename
                        or ":" in entry.filename or not path.parts or folded in seen
                        or (entry.external_attr >> 16) & 0o170000 == 0o120000):
                    raise ValueError(f"unsafe archive entry: {entry.filename}")
                seen.add(folded)
                if any(part.endswith((".", " ")) or part.split(".")[0].upper() in
                       {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(10)),
                        *(f"LPT{i}" for i in range(10))} for part in path.parts):
                    raise ValueError(f"nonportable archive entry: {entry.filename}")
                target = staging.joinpath(*path.parts)
                if entry.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with archive.open(entry) as source, target.open("xb") as output:
                        shutil.copyfileobj(source, output)
        read_manifest(staging)
        staging.rename(destination)


def read_manifest(sdk):
    manifest = json.loads((sdk / "sdk.json").read_text(encoding="utf-8"))
    if not isinstance(manifest, dict):
        raise ValueError("invalid SDK manifest")
    if manifest.get("format") != 1 or manifest.get("target") != TARGET:
        raise ValueError("unsupported SDK")
    if not re.fullmatch(r"nightly-\d{4}-\d{2}-\d{2}", str(manifest.get("toolchain", ""))):
        raise ValueError("SDK toolchain must be date-pinned")
    if not re.fullmatch(r"[0-9a-f]{40}", str(manifest.get("compiler_commit", ""))):
        raise ValueError("SDK compiler commit is missing or invalid")
    return manifest


def install(args):
    if not re.fullmatch(r"[0-9a-fA-F]{64}", args.sha256):
        raise ValueError("a trusted SHA-256 is required")
    with tempfile.TemporaryDirectory() as temporary:
        archive = Path(temporary) / "sdk.zip"
        if args.url:
            if not args.url.startswith("https://"):
                raise ValueError("only HTTPS downloads are supported")
            with urllib.request.urlopen(args.url, timeout=60) as response, archive.open("xb") as output:
                if not response.url.startswith("https://"):
                    raise ValueError("download redirected away from HTTPS")
                total = 0
                while data := response.read(1024 * 1024):
                    total += len(data)
                    if total > MAX_ARCHIVE_BYTES:
                        raise ValueError("archive too large")
                    output.write(data)
        else:
            if args.archive.stat().st_size > MAX_ARCHIVE_BYTES:
                raise ValueError("archive too large")
            shutil.copyfile(args.archive, archive)
        if checksum(archive) != args.sha256.lower():
            raise ValueError("SDK checksum mismatch")
        unpack(archive, args.destination.resolve())
    print(f"Installed SDK: {args.destination.resolve()}")


def configure(args):
    sdk, project = args.sdk.resolve(), args.project.resolve()
    manifest = read_manifest(sdk)
    if not (project / "Cargo.toml").is_file():
        raise ValueError("project must contain Cargo.toml")
    for name in (".cargo/config", ".cargo/config.toml", "rust-toolchain", "rust-toolchain.toml"):
        if (project / name).exists():
            raise ValueError(f"refusing to overwrite {project / name}")
    toolchain = manifest["toolchain"]
    info = compiler_info(toolchain)
    if info["commit-hash"] != manifest["compiler_commit"]:
        raise ValueError("installed compiler does not match SDK; install " + toolchain)
    sysroot = Path(rustc(toolchain, "--print", "sysroot"))
    linker = sysroot / "lib/rustlib" / info["host"] / "bin" / ("rust-lld.exe" if os.name == "nt" else "rust-lld")
    if not linker.is_file():
        raise ValueError(f"Rust linker missing: {linker}")
    flags = ["--sysroot", (sdk / "sysroot").as_posix(), "-Cpanic=abort", "-Clinker-flavor=gnu-lld"]
    flags += ["-Clink-arg=" + arg for arg in [
        "-T" + (sdk / "lib/linker.ld").as_posix(), "--no-pie", "-z", "noexecstack",
        "-L" + (sdk / "lib").as_posix(), "--start-group", (sdk / "lib/crt0.o").as_posix(),
        "-lmochi_user_newlib_runtime", "-lc", "-lm", "-lgcc", "--end-group"]]
    config = ("[build]\ntarget = " + json.dumps((sdk / f"targets/{TARGET}.json").as_posix(), ensure_ascii=False)
              + "\n[unstable]\njson-target-spec = true\n"
              + f"[target.{TARGET}]\nlinker = " + json.dumps(linker.as_posix(), ensure_ascii=False)
              + "\nrustflags = " + json.dumps(flags, ensure_ascii=False) + "\n")
    (project / ".cargo").mkdir(exist_ok=True)
    with (project / ".cargo/config.toml").open("x", encoding="utf-8") as output:
        output.write(config)
    with (project / "rust-toolchain.toml").open("x", encoding="utf-8") as output:
        output.write('[toolchain]\nchannel = ' + json.dumps(toolchain) + '\nprofile = "minimal"\n')
    print("Configured project. Run cargo build --release from " + str(project))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    package = commands.add_parser("pack")
    for option in ("std-lib", "panic-lib", "c-sdk", "target", "libgcc", "output"):
        package.add_argument("--" + option, type=Path, required=True)
    package.add_argument("--toolchain", required=True)
    package.add_argument("--license", type=Path, action="append", default=[])
    package.set_defaults(run=pack)
    installer = commands.add_parser("install")
    source = installer.add_mutually_exclusive_group(required=True)
    source.add_argument("--url", help="e.g. https://storage.mochios.org/rustc/<version>/sdk.zip")
    source.add_argument("--archive", type=Path)
    installer.add_argument("--sha256", required=True)
    installer.add_argument("--destination", required=True, type=Path)
    installer.set_defaults(run=install)
    setup = commands.add_parser("configure")
    setup.add_argument("--sdk", required=True, type=Path)
    setup.add_argument("--project", required=True, type=Path)
    setup.set_defaults(run=configure)
    args = parser.parse_args()
    try:
        args.run(args)
    except (ValueError, OSError, subprocess.CalledProcessError, zipfile.BadZipFile) as error:
        parser.exit(1, f"error: {error}\n")


if __name__ == "__main__":
    main()
