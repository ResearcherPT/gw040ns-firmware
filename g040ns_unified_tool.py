#!/usr/bin/env python3
"""
Unified VNPT GW040-NS raw-MTD firmware tool.

This single file merges the responsibilities of the original two scripts:

1. g040ns_pack.py
   - inspect HDR2 + FIT raw tclinux images
   - extract FIT/FDT/kernel/rootfs
   - repack a raw direct-MTD tclinux image

2. g040ns_mtd_flash.py
   - build rootfs.squashfs from an extracted rootfs directory
   - reuse kernel/FDT/HDR2 metadata from a base image
   - upload, flash, set dual-image bootflag, and optionally reboot

Supported raw image format:
    HDR2 header (0x100 bytes) + FIT payload + 0xff padding to partition size

This tool does NOT build the CSC trailer used by the web updater. It is for
raw tclinux/tclinux_slave partition images used with direct MTD write.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time
import zlib
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

HDR_SIZE = 0x100
DEFAULT_PARTITION_SIZE = 0x1E00000
FDT_MAGIC = 0xD00DFEED

FDT_BEGIN_NODE = 1
FDT_END_NODE = 2
FDT_PROP = 3
FDT_NOP = 4
FDT_END = 9

DEFAULT_HOST = os.getenv("G040NS_HOST", "192.168.1.1")
DEFAULT_USER = os.getenv("G040NS_USER", "admin")
DEFAULT_PASSWORD = os.getenv("G040NS_PASSWORD", "")
DEFAULT_REMOTE_TMP = os.getenv("G040NS_REMOTE_TMP", "/tmp/var/tmp")


# ---------------------------------------------------------------------------
# Basic helpers
# ---------------------------------------------------------------------------

class Fatal(RuntimeError):
    pass


def log(msg: str) -> None:
    print(f"[*] {msg}", flush=True)


def ok(msg: str) -> None:
    print(f"[+] {msg}", flush=True)


def warn(msg: str) -> None:
    print(f"[!] {msg}", flush=True)


def die(msg: str) -> None:
    raise Fatal(msg)


def parse_int(value: str) -> int:
    try:
        return int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid integer: {value!r}") from exc


def align4(value: int) -> int:
    return (value + 3) & ~3


def u32be(data: bytes) -> int:
    if len(data) != 4:
        die(f"expected u32 property, got {len(data)} bytes")
    return struct.unpack(">I", data)[0]


def u32le(value: int) -> bytes:
    return struct.pack("<I", value)


def sha1_words(data: bytes) -> str:
    digest = hashlib.sha1(data).digest()
    words = struct.unpack(">5I", digest)
    return " ".join(f"0x{word:08x}" for word in words)


def c_string(data: bytes) -> str:
    return data.rstrip(b"\x00").decode("ascii", "replace")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def need_tool(name: str) -> str:
    found = shutil.which(name)
    if not found:
        die(f"missing required tool in PATH: {name}")
    return found


def run_local(
    argv: list[str],
    *,
    stdin_path: Path | None = None,
    timeout: int | None = None,
    check: bool = False,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    stdin = None
    try:
        if stdin_path is not None:
            stdin = stdin_path.open("rb")
        cp = subprocess.run(
            argv,
            stdin=stdin,
            text=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
            env=env,
        )
        if check and cp.returncode != 0:
            out = cp.stdout.decode("utf-8", "replace")
            die(f"command failed rc={cp.returncode}: {' '.join(argv)}\n{out}")
        return cp
    finally:
        if stdin is not None:
            stdin.close()


def shq(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def ensure_file(path: Path, desc: str) -> None:
    if not path.is_file():
        die(f"{desc} not found or not a file: {path}")


def ensure_dir(path: Path, desc: str) -> None:
    if not path.is_dir():
        die(f"{desc} not found or not a directory: {path}")


def resolve_under_project(project_dir: Path, path: Path | None, default: Path | None = None) -> Path:
    """Resolve a CLI path. Relative paths are relative to --project-dir."""
    selected = path if path is not None else default
    if selected is None:
        die("internal error: missing path")
    selected = Path(selected).expanduser()
    if selected.is_absolute():
        return selected.resolve()
    return (project_dir / selected).resolve()


# ---------------------------------------------------------------------------
# FIT/FDT parser and raw image pack/unpack logic
# ---------------------------------------------------------------------------

class Fdt:
    def __init__(self, blob: bytes):
        if len(blob) < 40:
            die("FIT payload is too small to contain an FDT header")
        header = struct.unpack(">10I", blob[:40])
        (
            magic,
            self.total_size,
            self.off_struct,
            self.off_strings,
            self.off_reserve,
            self.version,
            self.last_comp_version,
            self.boot_cpuid,
            self.size_strings,
            self.size_struct,
        ) = header
        if magic != FDT_MAGIC:
            die("FIT payload is not an FDT/DTB")
        if self.total_size > len(blob):
            die(f"FDT total_size 0x{self.total_size:x} exceeds FIT size 0x{len(blob):x}")
        self.blob = blob
        self.props: dict[tuple[str, str], bytes] = {}
        self.prop_offsets: dict[tuple[str, str], tuple[int, int]] = {}
        self._parse()

    def _parse(self) -> None:
        strings = self.blob[self.off_strings : self.off_strings + self.size_strings]
        pos = self.off_struct
        end = self.off_struct + self.size_struct
        stack: list[str] = []

        while pos < end:
            token = struct.unpack_from(">I", self.blob, pos)[0]
            pos += 4

            if token == FDT_BEGIN_NODE:
                nul = self.blob.index(b"\x00", pos)
                name = self.blob[pos:nul].decode("ascii", "replace")
                pos = align4(nul + 1)
                stack.append(name)
            elif token == FDT_END_NODE:
                if stack:
                    stack.pop()
            elif token == FDT_PROP:
                length, nameoff = struct.unpack_from(">II", self.blob, pos)
                pos += 8
                data_start = pos
                data = self.blob[pos : pos + length]
                pos = align4(pos + length)
                nul = strings.index(b"\x00", nameoff)
                prop_name = strings[nameoff:nul].decode("ascii", "replace")
                path = "/" + "/".join(item for item in stack if item)
                self.props[(path, prop_name)] = data
                self.prop_offsets[(path, prop_name)] = (data_start, length)
            elif token == FDT_NOP:
                continue
            elif token == FDT_END:
                break
            else:
                die(f"bad FDT token 0x{token:x} at 0x{pos - 4:x}")

    def prop(self, path: str, name: str) -> bytes:
        key = (path, name)
        if key not in self.props:
            die(f"missing FIT property {path}:{name}")
        return self.props[key]

    def prop_offset(self, path: str, name: str) -> tuple[int, int]:
        key = (path, name)
        if key not in self.prop_offsets:
            die(f"missing FIT property offset {path}:{name}")
        return self.prop_offsets[key]


def read_raw_image(path: Path) -> tuple[bytearray, bytes, int]:
    raw = bytearray(path.read_bytes())
    if len(raw) < HDR_SIZE:
        die("image is smaller than HDR2 header")
    if raw[:4] != b"HDR2":
        die("image does not start with HDR2")
    hdr_size = struct.unpack_from("<I", raw, 4)[0]
    total_size = struct.unpack_from("<I", raw, 8)[0]
    if hdr_size != HDR_SIZE:
        die(f"unexpected HDR2 header size 0x{hdr_size:x}")
    if total_size > len(raw):
        die(f"HDR2 total_size 0x{total_size:x} exceeds file size 0x{len(raw):x}")
    fit = bytes(raw[HDR_SIZE:total_size])
    return raw, fit, total_size


def image_info(path: Path) -> dict[str, Any]:
    raw, fit, total_size = read_raw_image(path)
    header_crc = struct.unpack_from("<I", raw, 0x0C)[0]
    computed_crc = (~zlib.crc32(fit)) & 0xFFFFFFFF
    fdt = Fdt(fit)

    info: dict[str, Any] = {
        "path": str(path),
        "file_size": len(raw),
        "hdr_total_size": total_size,
        "fit_size": len(fit),
        "hdr_crc": header_crc,
        "computed_crc": computed_crc,
        "version": raw[0x10:0x30].rstrip(b"\x00").decode("ascii", "replace"),
        "product": raw[0x30:0x50].rstrip(b"\x00").decode("ascii", "replace"),
        "kernel_size_hdr": struct.unpack_from("<I", raw, 0x50)[0],
        "rootfs_size_hdr": struct.unpack_from("<I", raw, 0x54)[0],
    }

    for node in ("fdt@1", "kernel@1", "filesystem@1"):
        path_node = f"/images/{node}"
        data = fdt.prop(path_node, "data")
        data_offset, data_len = fdt.prop_offset(path_node, "data")
        info[node] = {
            "description": c_string(fdt.prop(path_node, "description")),
            "type": c_string(fdt.prop(path_node, "type")),
            "compression": c_string(fdt.prop(path_node, "compression")),
            "data_offset": data_offset,
            "data_len": data_len,
            "sha1": hashlib.sha1(data).hexdigest(),
            "stored_sha1": fdt.prop(f"{path_node}/hash@1", "value").hex(),
        }
    return info


def print_info(path: Path) -> None:
    info = image_info(path)
    print(f"path: {info['path']}")
    print(f"file_size: 0x{info['file_size']:x}")
    print(f"hdr_total_size: 0x{info['hdr_total_size']:x}")
    print(f"fit_size: 0x{info['fit_size']:x}")
    print(f"hdr_crc: 0x{info['hdr_crc']:08x}")
    print(f"computed_crc: 0x{info['computed_crc']:08x}")
    print(f"version: {info['version']!r}")
    print(f"product: {info['product']!r}")
    print(f"kernel_size_hdr: 0x{info['kernel_size_hdr']:x}")
    print(f"rootfs_size_hdr: 0x{info['rootfs_size_hdr']:x}")
    for node in ("fdt@1", "kernel@1", "filesystem@1"):
        item = info[node]
        print(
            f"{node}: offset=0x{item['data_offset']:x} len=0x{item['data_len']:x} "
            f"sha1={item['sha1']} stored={item['stored_sha1']}"
        )


def extract_image(raw_path: Path, out_dir: Path) -> None:
    ensure_file(raw_path, "raw image")
    _, fit, _ = read_raw_image(raw_path)
    fdt = Fdt(fit)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "fit.itb").write_bytes(fit)
    for node, name in (
        ("fdt@1", "fdt.dtb"),
        ("kernel@1", "kernel.lzma"),
        ("filesystem@1", "rootfs.squashfs"),
    ):
        (out_dir / name).write_bytes(fdt.prop(f"/images/{node}", "data"))
    print_info(raw_path)
    ok(f"extracted to: {out_dir}")


def dts_string(base_fit: Fdt, fdt_path: Path, kernel_path: Path, rootfs_path: Path) -> str:
    timestamp = u32be(base_fit.prop("/", "timestamp"))
    root_desc = c_string(base_fit.prop("/", "description"))
    fdt_desc = c_string(base_fit.prop("/images/fdt@1", "description"))
    kernel_desc = c_string(base_fit.prop("/images/kernel@1", "description"))
    rootfs_desc = c_string(base_fit.prop("/images/filesystem@1", "description"))
    load = u32be(base_fit.prop("/images/kernel@1", "load"))
    entry = u32be(base_fit.prop("/images/kernel@1", "entry"))

    fdt_data = fdt_path.read_bytes()
    kernel_data = kernel_path.read_bytes()
    rootfs_data = rootfs_path.read_bytes()

    return f"""/dts-v1/;

/ {{
    timestamp = <0x{timestamp:08x}>;
    description = "{root_desc}";
    #address-cells = <0x01>;

    images {{
        fdt@1 {{
            description = "{fdt_desc}";
            data = /incbin/("{fdt_path.name}");
            type = "flat_dt";
            arch = "arm";
            compression = "none";

            hash@1 {{
                value = <{sha1_words(fdt_data)}>;
                algo = "sha1";
            }};
        }};

        kernel@1 {{
            description = "{kernel_desc}";
            data = /incbin/("{kernel_path.name}");
            type = "kernel";
            arch = "arm";
            os = "linux";
            compression = "lzma";
            load = <0x{load:08x}>;
            entry = <0x{entry:08x}>;

            hash@1 {{
                value = <{sha1_words(kernel_data)}>;
                algo = "sha1";
            }};
        }};

        filesystem@1 {{
            description = "{rootfs_desc}";
            data = /incbin/("{rootfs_path.name}");
            type = "filesystem";
            arch = "arm";
            os = "linux";
            compression = "none";

            hash@1 {{
                value = <{sha1_words(rootfs_data)}>;
                algo = "sha1";
            }};
        }};
    }};

    configurations {{
        default = "conf@1";

        conf@1 {{
            description = "Boot Linux kernel with FDT blob";
            fdt = "fdt@1";
            kernel = "kernel@1";
            filesystem = "filesystem@1";
        }};
    }};
}};
"""


def run_dtc(dts_path: Path, out_fit: Path) -> None:
    dtc = need_tool("dtc")
    subprocess.run(
        [dtc, "-I", "dts", "-O", "dtb", "-p", "0", "-o", str(out_fit), str(dts_path)],
        check=True,
    )


def set_header_string(header: bytearray, offset: int, length: int, value: str) -> None:
    data = value.encode("ascii")
    if len(data) >= length:
        die(f"header string {value!r} is too long for {length} bytes")
    header[offset : offset + length] = b"\x00" * length
    header[offset : offset + len(data)] = data


def pack_image(
    base_raw: Path,
    rootfs: Path,
    out_raw: Path,
    partition_size: int,
    version: str | None,
    keep_tmp: Path | None,
) -> None:
    ensure_file(base_raw, "base raw image")
    ensure_file(rootfs, "rootfs squashfs")
    base, base_fit_blob, _ = read_raw_image(base_raw)
    base_fit = Fdt(base_fit_blob)

    tmp_ctx = tempfile.TemporaryDirectory(prefix="g040ns-pack-") if keep_tmp is None else None
    work = keep_tmp if keep_tmp is not None else Path(tmp_ctx.name)
    work.mkdir(parents=True, exist_ok=True)

    fdt_path = work / "fdt.dtb"
    kernel_path = work / "kernel.lzma"
    rootfs_path = work / "rootfs.squashfs"
    dts_path = work / "image.its"
    fit_path = work / "fit.itb"

    fdt_path.write_bytes(base_fit.prop("/images/fdt@1", "data"))
    kernel_path.write_bytes(base_fit.prop("/images/kernel@1", "data"))
    rootfs_path.write_bytes(rootfs.read_bytes())
    dts_path.write_text(dts_string(base_fit, fdt_path, kernel_path, rootfs_path), encoding="ascii")
    run_dtc(dts_path, fit_path)

    fit_blob = fit_path.read_bytes()
    total_size = HDR_SIZE + len(fit_blob)
    if total_size > partition_size:
        die(f"image 0x{total_size:x} exceeds partition size 0x{partition_size:x}")

    header = bytearray(base[:HDR_SIZE])
    header[0:4] = b"HDR2"
    header[4:8] = u32le(HDR_SIZE)
    header[8:12] = u32le(total_size)
    header[12:16] = u32le((~zlib.crc32(fit_blob)) & 0xFFFFFFFF)
    header[0x50:0x54] = u32le(len(base_fit.prop("/images/kernel@1", "data")))
    header[0x54:0x58] = u32le(rootfs.stat().st_size)
    if version is not None:
        set_header_string(header, 0x10, 0x20, version if version.endswith("\n") else version + "\n")

    image = bytes(header) + fit_blob
    image += b"\xFF" * (partition_size - len(image))
    out_raw.parent.mkdir(parents=True, exist_ok=True)
    out_raw.write_bytes(image)

    ok(f"wrote: {out_raw}")
    print_info(out_raw)
    if tmp_ctx is not None:
        tmp_ctx.cleanup()
    else:
        ok(f"kept work dir: {work}")


# ---------------------------------------------------------------------------
# Build rootfs.squashfs from extracted rootfs dir
# ---------------------------------------------------------------------------

def copy_rootfs_tree(src: Path, dst: Path) -> None:
    if dst.exists():
        shutil.rmtree(dst)
    dst.mkdir(parents=True)
    src = src.resolve()

    skipped: list[str] = []
    for root, dirs, files in os.walk(src, topdown=True, followlinks=False):
        root_path = Path(root)
        rel_root = root_path.relative_to(src)
        out_root = dst / rel_root
        out_root.mkdir(exist_ok=True)

        for name in list(dirs):
            in_path = root_path / name
            rel = in_path.relative_to(src)
            out_path = dst / rel
            st = os.lstat(in_path)
            mode = stat.S_IFMT(st.st_mode)
            if mode == stat.S_IFLNK:
                if out_path.exists() or out_path.is_symlink():
                    out_path.unlink()
                os.symlink(os.readlink(in_path), out_path)
                dirs.remove(name)
            elif mode == stat.S_IFDIR:
                out_path.mkdir(exist_ok=True)
                os.chmod(out_path, stat.S_IMODE(st.st_mode))
            else:
                skipped.append(str(rel))
                dirs.remove(name)

        for name in files:
            in_path = root_path / name
            rel = in_path.relative_to(src)
            out_path = dst / rel
            st = os.lstat(in_path)
            mode = stat.S_IFMT(st.st_mode)
            if mode == stat.S_IFREG:
                out_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(in_path, out_path, follow_symlinks=False)
            elif mode == stat.S_IFLNK:
                if out_path.exists() or out_path.is_symlink():
                    out_path.unlink()
                os.symlink(os.readlink(in_path), out_path)
            else:
                skipped.append(str(rel))

    (dst / "dev").mkdir(exist_ok=True)
    if skipped:
        log(f"skipped {len(skipped)} special non-regular entries from extracted tree; base pseudo restores device nodes")


def maybe_encode_plain_asp(staging: Path) -> list[Path]:
    encoded: list[Path] = []
    for path in staging.rglob("*.asp"):
        if not path.is_file():
            continue
        data = path.read_bytes()
        lower = data.lower()
        if b"<html" in lower or b"<%" in data:
            path.write_bytes(bytes(b ^ 0xFF for b in data))
            encoded.append(path.relative_to(staging))
    return encoded


def extract_base_rootfs(base_raw: Path, work: Path) -> Path:
    _, fit, _ = read_raw_image(base_raw)
    fdt = Fdt(fit)
    out = work / "base_rootfs.squashfs"
    out.write_bytes(fdt.prop("/images/filesystem@1", "data"))
    return out


def make_device_pseudo(base_rootfs: Path, work: Path) -> Path:
    need_tool("unsquashfs")
    full = work / "base_rootfs.pseudo"
    devices = work / "device_nodes.pseudo"
    cp = run_local(["unsquashfs", "-pf", str(full), str(base_rootfs)], timeout=None)
    if cp.returncode != 0:
        die(cp.stdout.decode("utf-8", "replace"))
    keep: list[str] = []
    for line in full.read_text("utf-8", "replace").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//"):
            continue
        parts = line.split()
        if (
            len(parts) == 8
            and parts[1] in {"B", "C"}
            and all(part.isdigit() for part in parts[2:])
        ):
            keep.append(line)
    devices.write_text("\n".join(keep) + ("\n" if keep else ""), encoding="utf-8")
    log(f"device pseudo entries: {len(keep)}")
    return devices


def build_rootfs_from_dir(rootfs_dir: Path, base_raw: Path, work: Path, auto_encode_asp: bool) -> Path:
    need_tool("mksquashfs")
    ensure_dir(rootfs_dir, "extracted rootfs directory")
    ensure_file(base_raw, "base raw image")
    work.mkdir(parents=True, exist_ok=True)

    base_rootfs = extract_base_rootfs(base_raw, work)
    device_pseudo = make_device_pseudo(base_rootfs, work)

    staging = work / "rootfs_staging"
    log(f"copy extracted rootfs into staging: {staging}")
    copy_rootfs_tree(rootfs_dir, staging)

    if auto_encode_asp:
        encoded = maybe_encode_plain_asp(staging)
        if encoded:
            ok("auto-encoded plain ASP files: " + ", ".join(str(p) for p in encoded))

    out = work / "rootfs.squashfs"
    if out.exists():
        out.unlink()
    cmd = [
        "mksquashfs",
        str(staging),
        str(out),
        "-comp",
        "lzma",
        "-b",
        "131072",
        "-no-xattrs",
        "-no-tailends",
        "-all-root",
        "-pf",
        str(device_pseudo),
    ]
    log("building SquashFS")
    cp = run_local(cmd, timeout=None)
    text = cp.stdout.decode("utf-8", "replace")
    print(text, flush=True)
    if cp.returncode != 0:
        die("mksquashfs failed")
    ok(f"built rootfs: {out} sha256={sha256_file(out)}")
    return out


def pack_raw_image(base_raw: Path, rootfs_squashfs: Path, out_raw: Path, work: Path, version: str | None, partition_size: int) -> Path:
    log("packing HDR2/FIT raw MTD image")
    pack_image(
        base_raw=base_raw,
        rootfs=rootfs_squashfs,
        out_raw=out_raw,
        partition_size=partition_size,
        version=version,
        keep_tmp=work / "fit_work",
    )
    info = image_info(out_raw)
    if info["hdr_crc"] != info["computed_crc"]:
        die("HDR2 CRC mismatch after pack")
    if info["file_size"] != partition_size:
        die(f"bad output size: {info['file_size']} != {partition_size}")
    for node in ("fdt@1", "kernel@1", "filesystem@1"):
        item = info[node]
        if item["sha1"] != item["stored_sha1"]:
            die(f"FIT sha1 mismatch for {node}")
    ok(f"packed raw image: {out_raw} sha256={sha256_file(out_raw)}")
    return out_raw


def build_image_from_dir(
    base_raw: Path,
    rootfs_dir: Path,
    work_dir: Path,
    out_raw: Path,
    version: str | None,
    auto_encode_asp: bool,
    partition_size: int,
) -> Path:
    work_dir.mkdir(parents=True, exist_ok=True)
    out_raw.parent.mkdir(parents=True, exist_ok=True)
    rootfs = build_rootfs_from_dir(rootfs_dir, base_raw, work_dir, auto_encode_asp)
    return pack_raw_image(base_raw, rootfs, out_raw, work_dir, version, partition_size)


# ---------------------------------------------------------------------------
# SSH / device flashing logic
# ---------------------------------------------------------------------------

class SshDevice:
    def __init__(
        self,
        host: str,
        user: str,
        password: str,
        port: int = 22,
        retry_forever: bool = False,
        retry_delay: int = 8,
    ) -> None:
        self.host = host
        self.user = user
        self.password = password
        self.port = port
        self.retry_forever = retry_forever
        self.retry_delay = retry_delay

    def _ssh_env(self) -> dict[str, str]:
        env = os.environ.copy()
        env["SSHPASS"] = self.password
        return env

    def _ssh_base(self) -> list[str]:
        return [
            "sshpass",
            "-e",
            "ssh",
            "-p",
            str(self.port),
            "-o",
            "PreferredAuthentications=password",
            "-o",
            "PubkeyAuthentication=no",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "LogLevel=ERROR",
            "-o",
            "ServerAliveInterval=5",
            "-o",
            "ServerAliveCountMax=1",
            "-o",
            "ConnectTimeout=10",
            f"{self.user}@{self.host}",
        ]

    def run(
        self,
        cmd: str,
        *,
        check: bool = True,
        timeout: int | None = 120,
        retry: bool | None = None,
    ) -> str:
        do_retry = self.retry_forever if retry is None else retry
        attempt = 0
        while True:
            attempt += 1
            cp = run_local(self._ssh_base() + [cmd], timeout=timeout, env=self._ssh_env())
            out = cp.stdout.decode("utf-8", "replace")
            if cp.returncode == 0 or not check:
                return out
            if not do_retry:
                die(f"ssh command failed rc={cp.returncode}: {cmd}\n{out}")
            warn(f"ssh failed rc={cp.returncode}; retrying in {self.retry_delay}s: {cmd}")
            if out.strip():
                print(out.strip(), flush=True)
            time.sleep(self.retry_delay)

    def upload(self, local: Path, remote: str) -> None:
        size = local.stat().st_size
        attempt = 0
        while True:
            attempt += 1
            log(f"upload attempt {attempt}: {local} -> {self.host}:{remote} ({size} bytes)")
            cp = run_local(self._ssh_base() + [f"cat > {shq(remote)}"], stdin_path=local, timeout=None, env=self._ssh_env())
            out = cp.stdout.decode("utf-8", "replace")
            if cp.returncode == 0:
                remote_size = self.remote_size(remote)
                if remote_size == size:
                    ok(f"remote upload size OK: {remote_size} bytes")
                    return
                warn(f"remote upload size mismatch: local={size} remote={remote_size}")
            else:
                warn(f"upload failed rc={cp.returncode}")
                if out.strip():
                    print(out.strip(), flush=True)
            if not self.retry_forever:
                die("upload failed")
            time.sleep(self.retry_delay)

    def stream_sha256(self, remote: str) -> str:
        attempt = 0
        while True:
            attempt += 1
            log(f"stream sha256 attempt {attempt}: {remote}")
            cp = run_local(self._ssh_base() + [f"cat {shq(remote)}"], timeout=None, env=self._ssh_env())
            if cp.returncode == 0:
                return hashlib.sha256(cp.stdout).hexdigest()
            out = cp.stdout.decode("utf-8", "replace")
            warn(f"stream failed rc={cp.returncode}: {out.strip()}")
            if not self.retry_forever:
                die("remote stream failed")
            time.sleep(self.retry_delay)

    def remote_size(self, remote: str) -> int:
        out = self.run(f"ls -l {shq(remote)}", timeout=30)
        for line in out.splitlines():
            if remote in line:
                parts = line.split()
                if len(parts) >= 5:
                    try:
                        return int(parts[4])
                    except ValueError:
                        pass
        return 0

    def wait_shell(self, expected_cmdline: str | None = None) -> str:
        while True:
            out = self.run("cat /proc/cmdline", check=False, timeout=30, retry=False)
            if out.strip():
                if expected_cmdline is None or expected_cmdline in out:
                    return out.strip()
                warn(f"shell is up but cmdline does not match yet: {out.strip()}")
            time.sleep(self.retry_delay)


def require_password(password: str) -> None:
    if not password:
        die("missing SSH password; pass --password or set G040NS_PASSWORD")


def detect_active_slot(cmdline: str) -> str:
    if "root=/dev/mtdblock6" in cmdline or "bootflag=1" in cmdline:
        return "tclinux_slave"
    if "root=/dev/mtdblock3" in cmdline or "bootflag=0" in cmdline:
        return "tclinux"
    die(f"cannot detect active slot from cmdline: {cmdline}")


def inactive_slot(active: str) -> str:
    return "tclinux" if active == "tclinux_slave" else "tclinux_slave"


def slot_flag(slot: str) -> str:
    if slot == "tclinux":
        return "0"
    if slot == "tclinux_slave":
        return "1"
    die(f"bad slot: {slot}")


def expected_root_for_slot(slot: str) -> str:
    return "root=/dev/mtdblock3" if slot == "tclinux" else "root=/dev/mtdblock6"


def preflight_device(dev: SshDevice) -> tuple[str, str]:
    log("device preflight")
    out = dev.run("cat /proc/cmdline; echo __M__; cat /proc/mtd", timeout=60)
    if "__M__" not in out:
        die("unexpected preflight output")
    cmdline, mtd = out.split("__M__", 1)
    cmdline = cmdline.strip()
    if '"tclinux"' not in mtd or '"tclinux_slave"' not in mtd or '"reservearea"' not in mtd:
        die("required MTD partitions not present")
    active = detect_active_slot(cmdline)
    ok(f"active slot: {active}")
    return active, cmdline


def upload_and_verify(dev: SshDevice, image: Path, remote_tmp: str) -> str:
    remote = f"{remote_tmp.rstrip('/')}/{image.name}"
    dev.run(f"mkdir -p {shq(remote_tmp)}", check=False, timeout=30)
    dev.run(f"rm -f {shq(remote)} {shq(remote_tmp.rstrip('/') + '/readback_' + image.name)}", check=False, timeout=30)
    dev.upload(image, remote)
    local_sha = sha256_file(image)
    remote_sha = dev.stream_sha256(remote)
    if remote_sha != local_sha:
        die(f"upload sha256 mismatch: local={local_sha} remote={remote_sha}")
    ok(f"remote upload sha256 OK: {remote_sha}")
    return remote


def flash_and_verify(dev: SshDevice, image: Path, remote_image: str, target_slot: str, remote_tmp: str, partition_size: int) -> None:
    local_sha = sha256_file(image)
    size = image.stat().st_size
    if size != partition_size:
        die(f"refusing to flash non-partition-sized image: {size} != {partition_size}")
    log(f"flashing {target_slot}")
    dev.run(f"/userfs/bin/mtd -f write {shq(remote_image)} {size} 0 {shq(target_slot)}", timeout=None)
    ok("mtd write returned successfully")

    readback = f"{remote_tmp.rstrip('/')}/readback_{target_slot}.bin"
    dev.run(f"rm -f {shq(remote_image)} {shq(readback)}", check=False, timeout=30)
    dev.run(f"/userfs/bin/mtd readflash {shq(readback)} {size} 0 {shq(target_slot)}", timeout=None)
    remote_sha = dev.stream_sha256(readback)
    if remote_sha != local_sha:
        die(f"MTD readback sha256 mismatch: local={local_sha} remote={remote_sha}")
    ok(f"MTD readback sha256 OK: {remote_sha}")
    dev.run(f"rm -f {shq(readback)}", check=False, timeout=30)


def set_bootflag(dev: SshDevice, target_slot: str) -> None:
    flag = slot_flag(target_slot)
    log(f"setting bootflag for {target_slot}: {flag}")
    dev.run(
        "echo -n "
        + shq(flag)
        + " > /tmp/dual_image_boot_flag_new; "
        + "/userfs/bin/mtd writeflash /tmp/dual_image_boot_flag_new 1 2097152 reservearea; "
        + "/userfs/bin/mtd readflash /tmp/dual_image_boot_flag_after 1 2097152 reservearea",
        timeout=120,
    )
    remote_sha = dev.stream_sha256("/tmp/dual_image_boot_flag_after")
    expected = hashlib.sha256((flag.encode("ascii") + b"\xff" * 255)).hexdigest()
    if remote_sha != expected:
        warn("bootflag readback hash did not match 256-byte padded expectation; checking first byte via stream")
        cp = run_local(dev._ssh_base() + ["cat /tmp/dual_image_boot_flag_after"], timeout=60, env=dev._ssh_env())
        data = cp.stdout
        if not data or data[0:1] != flag.encode("ascii"):
            die(f"bootflag readback failed: first byte={data[0:1]!r}")
    ok("bootflag set")


def reboot_and_wait(dev: SshDevice, target_slot: str) -> None:
    log("rebooting device")
    dev.run("sync; /sbin/reboot", check=False, timeout=20, retry=False)
    expected = expected_root_for_slot(target_slot)
    ok("reboot command sent; waiting for shell")
    cmdline = dev.wait_shell(expected_cmdline=expected)
    ok(f"device booted expected slot: {cmdline}")


def flash_existing_image(
    image: Path,
    host: str,
    user: str,
    password: str,
    port: int,
    remote_tmp: str,
    target_slot: str | None,
    allow_active: bool,
    no_reboot: bool,
    retry_forever: bool,
    retry_delay: int,
    partition_size: int,
) -> None:
    need_tool("sshpass")
    require_password(password)
    ensure_file(image, "image")
    dev = SshDevice(host, user, password, port, retry_forever, retry_delay)
    active, _ = preflight_device(dev)
    target = target_slot or inactive_slot(active)
    if target == active and not allow_active:
        die(f"refusing to flash active slot {target}; pass --allow-active to override")
    remote = upload_and_verify(dev, image, remote_tmp)
    flash_and_verify(dev, image, remote, target, remote_tmp, partition_size)
    set_bootflag(dev, target)
    if no_reboot:
        ok("flash complete; reboot skipped")
    else:
        reboot_and_wait(dev, target)


# ---------------------------------------------------------------------------
# CLI command handlers
# ---------------------------------------------------------------------------

def cmd_inspect(args: argparse.Namespace) -> None:
    project = args.project_dir.resolve()
    image = resolve_under_project(project, args.image)
    ensure_file(image, "image")
    print_info(image)


def cmd_extract(args: argparse.Namespace) -> None:
    project = args.project_dir.resolve()
    image = resolve_under_project(project, args.image)
    out_dir = resolve_under_project(project, args.out_dir, args.output_dir / "extracted")
    extract_image(image, out_dir)


def cmd_pack(args: argparse.Namespace) -> None:
    project = args.project_dir.resolve()
    base = resolve_under_project(project, args.base)
    rootfs = resolve_under_project(project, args.rootfs)
    out_raw = resolve_under_project(project, args.out, args.output_dir / "tclinux_mtd.bin")
    keep_work = None
    if args.keep_work_dir is not None:
        keep_work = resolve_under_project(project, args.keep_work_dir)
    pack_image(base, rootfs, out_raw, args.partition_size, args.version, keep_work)


def cmd_build(args: argparse.Namespace) -> None:
    project = args.project_dir.resolve()
    base = resolve_under_project(project, args.base)
    rootfs_dir = resolve_under_project(project, args.rootfs_dir)
    work_dir = resolve_under_project(project, args.work_dir, args.output_dir / "work")
    out_raw = resolve_under_project(project, args.out, args.output_dir / "tclinux_mtd.bin")
    image = build_image_from_dir(
        base,
        rootfs_dir,
        work_dir,
        out_raw,
        args.version,
        args.auto_encode_asp,
        args.partition_size,
    )
    ok(f"build complete: {image}")


def cmd_flash(args: argparse.Namespace) -> None:
    project = args.project_dir.resolve()
    image = resolve_under_project(project, args.image)
    flash_existing_image(
        image=image,
        host=args.host,
        user=args.user,
        password=args.password,
        port=args.port,
        remote_tmp=args.remote_tmp,
        target_slot=args.target_slot,
        allow_active=args.allow_active,
        no_reboot=args.no_reboot,
        retry_forever=args.retry_forever,
        retry_delay=args.retry_delay,
        partition_size=args.partition_size,
    )


def cmd_build_flash(args: argparse.Namespace) -> None:
    project = args.project_dir.resolve()
    base = resolve_under_project(project, args.base)
    rootfs_dir = resolve_under_project(project, args.rootfs_dir)
    work_dir = resolve_under_project(project, args.work_dir, args.output_dir / "work")
    out_raw = resolve_under_project(project, args.out, args.output_dir / "tclinux_mtd.bin")
    image = build_image_from_dir(
        base,
        rootfs_dir,
        work_dir,
        out_raw,
        args.version,
        args.auto_encode_asp,
        args.partition_size,
    )
    flash_existing_image(
        image=image,
        host=args.host,
        user=args.user,
        password=args.password,
        port=args.port,
        remote_tmp=args.remote_tmp,
        target_slot=args.target_slot,
        allow_active=args.allow_active,
        no_reboot=args.no_reboot,
        retry_forever=args.retry_forever,
        retry_delay=args.retry_delay,
        partition_size=args.partition_size,
    )


def cmd_status(args: argparse.Namespace) -> None:
    need_tool("sshpass")
    require_password(args.password)
    dev = SshDevice(args.host, args.user, args.password, args.port, args.retry_forever, args.retry_delay)
    active, cmdline = preflight_device(dev)
    target = args.target_slot or inactive_slot(active)
    print()
    print(f"host:        {args.host}")
    print(f"active:      {active}")
    print(f"default dst: {target}")
    print(f"boot flag:   {slot_flag(active)}")
    print(f"cmdline:     {cmdline}")
    print()
    out = dev.run(
        "echo __PROC_MTD__; cat /proc/mtd; "
        "echo __TMP__; cat /proc/mounts | grep -E ' /tmp |/tmp/userdata|/tmp/etc/safegate' 2>&1; "
        "echo __BOOTFLAG__; /userfs/bin/mtd readflash /tmp/dual_image_boot_flag_status 1 2097152 reservearea >/tmp/mtd_bootflag_status.log 2>&1; "
        "cat /tmp/mtd_bootflag_status.log; ls -l /tmp/dual_image_boot_flag_status",
        timeout=120,
    )
    print(out)


# ---------------------------------------------------------------------------
# Argparse
# ---------------------------------------------------------------------------

def add_common_path_flags(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--project-dir",
        type=Path,
        default=Path.cwd(),
        help="base directory used to resolve relative paths; default: current directory",
    )
    p.add_argument(
        "--output-dir",
        type=Path,
        default=Path("out"),
        help="default output directory for commands that can auto-pick an output path; default: ./out under --project-dir",
    )


def add_partition_flag(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--partition-size",
        type=parse_int,
        default=DEFAULT_PARTITION_SIZE,
        help="raw MTD partition size; accepts decimal or 0x...; default: 0x1e00000",
    )


def add_build_flags(p: argparse.ArgumentParser) -> None:
    p.add_argument("--base", type=Path, required=True, help="base raw tclinux image used for HDR2/FIT/kernel/FDT metadata")
    p.add_argument("--rootfs-dir", type=Path, required=True, help="modded extracted rootfs directory")
    p.add_argument("--work-dir", type=Path, help="working directory; default: --output-dir/work")
    p.add_argument("--out", type=Path, help="output raw MTD image; default: --output-dir/tclinux_mtd.bin")
    p.add_argument("--version", help="optional HDR2 version string")
    p.add_argument(
        "--no-auto-encode-asp",
        dest="auto_encode_asp",
        action="store_false",
        help="do not XOR-encode plain-looking .asp files in staging",
    )
    p.set_defaults(auto_encode_asp=True)
    add_partition_flag(p)


def add_flash_flags(p: argparse.ArgumentParser, include_partition: bool = True) -> None:
    p.add_argument("--host", default=DEFAULT_HOST, help="SSH host; default from G040NS_HOST or 192.168.1.1")
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--user", default=DEFAULT_USER, help="SSH user; default from G040NS_USER or admin")
    p.add_argument("--password", default=DEFAULT_PASSWORD, help="SSH password; default from G040NS_PASSWORD")
    p.add_argument("--remote-tmp", default=DEFAULT_REMOTE_TMP, help="remote temp directory; default from G040NS_REMOTE_TMP or /tmp/var/tmp")
    p.add_argument("--target-slot", choices=["tclinux", "tclinux_slave"], help="default: inactive slot")
    p.add_argument("--allow-active", action="store_true", help="allow flashing the currently active slot")
    p.add_argument("--no-reboot", action="store_true", help="flash and set bootflag, but do not reboot")
    p.add_argument("--retry-forever", action="store_true", help="keep retrying SSH/upload/readback forever")
    p.add_argument("--retry-delay", type=int, default=8)
    if include_partition:
        add_partition_flag(p)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Unified GW040-NS raw-MTD image pack/build/flash tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_info = sub.add_parser("inspect", help="inspect a raw tclinux image")
    add_common_path_flags(p_info)
    p_info.add_argument("image", type=Path)
    p_info.set_defaults(func=cmd_inspect)

    p_extract = sub.add_parser("extract", help="extract FIT, kernel, FDT and rootfs")
    add_common_path_flags(p_extract)
    p_extract.add_argument("image", type=Path)
    p_extract.add_argument("--out-dir", type=Path, help="extraction directory; default: --output-dir/extracted")
    p_extract.set_defaults(func=cmd_extract)

    p_pack = sub.add_parser("pack", help="pack a raw direct-MTD tclinux image from rootfs.squashfs")
    add_common_path_flags(p_pack)
    p_pack.add_argument("--base", type=Path, required=True, help="base raw tclinux image")
    p_pack.add_argument("--rootfs", type=Path, required=True, help="new rootfs.squashfs")
    p_pack.add_argument("--out", type=Path, help="output raw image; default: --output-dir/tclinux_mtd.bin")
    p_pack.add_argument("--version", help="optional HDR2 version string")
    p_pack.add_argument("--keep-work-dir", type=Path, help="keep intermediate FIT/DTS files here")
    add_partition_flag(p_pack)
    p_pack.set_defaults(func=cmd_pack)

    p_build = sub.add_parser("build", help="build raw MTD image from extracted rootfs directory")
    add_common_path_flags(p_build)
    add_build_flags(p_build)
    p_build.set_defaults(func=cmd_build)

    p_flash = sub.add_parser("flash", help="upload/flash an already-built raw MTD image")
    add_common_path_flags(p_flash)
    p_flash.add_argument("--image", type=Path, required=True)
    add_flash_flags(p_flash)
    p_flash.set_defaults(func=cmd_flash)

    p_status = sub.add_parser("status", help="check modem slot and MTD layout")
    add_common_path_flags(p_status)
    add_flash_flags(p_status)
    p_status.set_defaults(func=cmd_status)

    p_bf = sub.add_parser("build-flash", help="build, upload, flash, set bootflag and reboot")
    add_common_path_flags(p_bf)
    add_build_flags(p_bf)
    add_flash_flags(p_bf, include_partition=False)
    p_bf.set_defaults(func=cmd_build_flash)

    return parser


def main(argv: list[str]) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except Fatal as e:
        print(f"error: {e}", file=sys.stderr)
        raise SystemExit(1)
    except subprocess.CalledProcessError as e:
        print(f"error: command failed rc={e.returncode}: {e.cmd}", file=sys.stderr)
        raise SystemExit(1)
