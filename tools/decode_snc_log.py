#!/usr/bin/env python3

# The Tunnel Cat Project
# Copyright (C) NavLink, 2026
# Лицензировано под лицензией Apache 2.0

"""
decode_snc_log.py — decode binlog-framed SNC client logs back to plain text.

Companion to tunnel_cat/binlog (the Go codec) — implements the exact same
wire format. This is the ONE place that understands binlog-framed content
end to end: the arbiter deliberately does NOT decode uploads server-side
(see snc-arbiter/log_upload_client_api.go and nodeLogStore's doc comment,
tunnel_cat/snc-arbiter/log_store.go, for why that was tried and reverted --
decompressing untrusted client payloads on the ingest hot path was a real,
avoidable risk). So every stored artifact -- a periodic auto-upload sitting
on the SSHFS mount, or a user's manually-shared "Share Logs" ZIP -- reaches
a human still wrapped exactly as received, and this script is what turns it
into something readable. "Download, unpack, study" for a given user/time
range means: find the right file(s) under the per-user directory (see
nodeLogStore's layout), then run this script on them.

Wire format, one record (must match tunnel_cat/binlog/binlog.go exactly):
    [2B start magic 0xC5A7][1B tag][1-10B uvarint payload len][payload]
    [2B CRC16/CCITT-FALSE][2B end magic 0x7A5C]

Layers this script unwraps automatically, in order, per file (including per
zip entry): outer .zip (if the input is one) -> gzip (auto-detected by its
magic bytes, whether or not the filename says .gz) -> binlog framing (if
present). A file/entry only needs to be gzip-compressed, only binlog-framed,
both, or neither -- every combination is handled the same way, and the
output is always the most-decoded human-readable form available.

Usage:
    python decode_snc_log.py snc-logs.zip                    # decode, write snc-logs.decoded.zip
    python decode_snc_log.py snc-logs.zip -o out.zip          # decode to a specific path
    python decode_snc_log.py 20260815_120000_abc123.zip       # a single stored upload (arbiter layout)
    python decode_snc_log.py snc_lifecycle.log                # decode a single file to stdout
    python decode_snc_log.py snc_lifecycle.log -o out.log     # decode a single file to a path
    python decode_snc_log.py snc-logs.zip --list-tags         # see which topics are present
    python decode_snc_log.py snc-logs.zip --tag socks5 --tag bypass -o vpn-only.zip

A file/entry that isn't binlog-framed at all (e.g. today's KotlinLog/SwiftLog
plain-text files, or an already-legacy Go .log file, gzipped or not) is
decompressed if it was gzipped and otherwise passed through byte-for-byte --
this tool never guesses at content it can't positively identify; it only
replaces bytes with something else once it actually found a valid framed
record (for binlog) or a valid gzip member (for the outer compression).
"""

from __future__ import annotations

import argparse
import gzip
import struct
import sys
import zipfile
from pathlib import Path

START_MAGIC = 0xC5A7
END_MAGIC = 0x7A5C
MIN_RECORD_LEN = 2 + 1 + 1 + 2 + 2  # start + tag + shortest varint + crc + end

# Must stay in sync with binlog.TagNames (tunnel_cat/binlog/binlog.go) and
# snc/core/log_tags.go's subsystemTags grouping.
TAG_NAMES = {
    0: "generic",
    1: "tunnel",
    2: "socks5",
    3: "bypass",
    4: "upload",
    5: "update",
    6: "system",
}
TAG_NAME_TO_ID = {name: tag for tag, name in TAG_NAMES.items()}


def crc16(data: bytes) -> int:
    """CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF) — must match binlog.go's crc16."""
    crc = 0xFFFF
    for b in data:
        crc = ((crc << 8) & 0xFFFF) ^ CRC16_TABLE[((crc >> 8) ^ b) & 0xFF]
    return crc


def _build_crc16_table() -> list[int]:
    table = []
    for i in range(256):
        crc = i << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
        table.append(crc)
    return table


CRC16_TABLE = _build_crc16_table()


def _read_uvarint(data: bytes, pos: int) -> tuple[int | None, int]:
    """Mirrors encoding/binary.Uvarint. Returns (value, bytes_consumed) or (None, 0)."""
    result = 0
    shift = 0
    for i in range(pos, min(pos + 10, len(data))):
        b = data[i]
        if b < 0x80:
            result |= b << shift
            return result, (i - pos) + 1
        result |= (b & 0x7F) << shift
        shift += 7
    return None, 0


def _find_magic(data: bytes, magic: int, start: int) -> int:
    hi, lo = (magic >> 8) & 0xFF, magic & 0xFF
    pair = bytes((hi, lo))
    return data.find(pair, start)


def _decode_one_record(b: bytes) -> tuple[int | None, bytes | None, int]:
    """b must begin exactly at a start-magic occurrence. Returns (tag, payload, consumed) or (None, None, 0)."""
    if len(b) < MIN_RECORD_LEN:
        return None, None, 0
    pos = 2  # skip start magic
    tag = b[pos]
    pos += 1

    payload_len, n = _read_uvarint(b, pos)
    if payload_len is None or n <= 0:
        return None, None, 0
    pos += n

    body_end = pos + payload_len
    if payload_len > len(b) or body_end + 4 > len(b):
        return None, None, 0  # truncated

    got_crc = struct.unpack_from(">H", b, body_end)[0]
    want_crc = crc16(b[2:body_end])  # tag + len-varint + payload
    if got_crc != want_crc:
        return None, None, 0

    end_magic = struct.unpack_from(">H", b, body_end + 2)[0]
    if end_magic != END_MAGIC:
        return None, None, 0

    return tag, b[pos:body_end], body_end + 4


def decode_records(data: bytes) -> tuple[list[tuple[int, bytes]], int]:
    """Returns (list of (tag, payload), corrupt_record_count). Mirrors
    binlog.DecodeRecords exactly -- this is what topic filtering (--tag)
    operates on."""
    records: list[tuple[int, bytes]] = []
    corrupt = 0
    i = 0
    while i < len(data):
        off = _find_magic(data, START_MAGIC, i)
        if off < 0:
            break
        i = off
        tag, payload, consumed = _decode_one_record(data[i:])
        if payload is None:
            corrupt += 1
            i += 1  # resync: advance one byte and keep scanning
            continue
        records.append((tag, payload))
        i += consumed
    return records, corrupt


def decode(data: bytes, tags: set[int] | None = None) -> tuple[bytes, int]:
    """Returns (decoded_text, corrupt_record_count). Mirrors binlog.Decode
    when tags is None (every record included); when tags is given, only
    records whose tag is in the set are kept -- e.g. tags={TAG_NAME_TO_ID['bypass']}
    to look only at bypass-routing lines."""
    records, corrupt = decode_records(data)
    out = bytearray()
    for tag, payload in records:
        if tags is None or tag in tags:
            out += payload
    return bytes(out), corrupt


# MAX_GUNZIP_BYTES bounds this script's own decompression -- unlike the
# arbiter (which never decompresses client payloads at all, see
# apiLogClientUpload's comment), this tool runs locally, off any network
# path, against a file the operator already chose to open. A bound is still
# sensible hygiene (a genuinely corrupt file shouldn't be able to hang the
# process or exhaust memory), just not the same load-bearing security
# control it would be on a server. 256 MB is generous for anything this
# tool is meant to open.
MAX_GUNZIP_BYTES = 256 << 20

GZIP_MAGIC = b"\x1f\x8b"


def _maybe_gunzip(data: bytes) -> tuple[bytes, bool]:
    """Returns (possibly-decompressed data, was_gzip). Never raises -- a
    file that merely starts with the gzip magic bytes by coincidence but
    isn't actually valid gzip is returned unchanged, same "never guess
    wrong" contract as the binlog side."""
    if not data.startswith(GZIP_MAGIC):
        return data, False
    try:
        out = gzip.decompress(data[: MAX_GUNZIP_BYTES + 1] if len(data) > MAX_GUNZIP_BYTES else data)
    except Exception:
        return data, False
    if len(out) > MAX_GUNZIP_BYTES:
        return data, False
    return out, True


def maybe_decode_file(name: str, data: bytes, tags: set[int] | None = None) -> tuple[bytes, bool, int]:
    """Unwraps gzip (if present, auto-detected) then binlog framing (if
    present) from data. Never guesses -- a plain-text file (KotlinLog/
    SwiftLog today, legacy Go logs, anything else), gzipped or not, always
    ends up as itself: gunzipped if it was gzip-compressed, otherwise
    passed through byte-for-byte. A --tag filter only narrows actual
    binlog-framed content; it never empties a file that was never framed
    to begin with.

    Returns (output_bytes, was_binlog, corrupt_count). was_binlog reflects
    only the binlog layer (for the --list-tags / decoded-vs-passthrough
    reporting in process_zip/process_single_file) -- a file that was
    gunzipped but had no binlog framing inside still reports was_binlog
    False, since there's nothing tag-related to report about it.
    """
    inner, was_gzip = _maybe_gunzip(data)

    records, corrupt = decode_records(inner)
    if not records:
        # Zero decodable records: either genuinely not binlog-framed, or
        # 100% corrupt. Either way, the most-decoded honest output is
        # whatever gunzip already produced (or the original bytes, if it
        # wasn't gzip either) -- never discard content we can't improve on.
        return inner, False, corrupt

    out = bytearray()
    for tag, payload in records:
        if tags is None or tag in tags:
            out += payload
    return bytes(out), True, corrupt


def process_zip(src: Path, dst: Path, tags: set[int] | None) -> None:
    with zipfile.ZipFile(src, "r") as zin, zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zout:
        for info in zin.infolist():
            raw = zin.read(info.filename)
            out, was_binlog, corrupt = maybe_decode_file(info.filename, raw, tags)
            if was_binlog:
                note = f" ({corrupt} corrupt record(s) skipped)" if corrupt else ""
                print(f"  decoded: {info.filename} ({len(raw)} -> {len(out)} bytes){note}", file=sys.stderr)
            else:
                print(f"  passthrough (not binlog): {info.filename}", file=sys.stderr)
            zout.writestr(info, out)
    print(f"wrote {dst}", file=sys.stderr)


def process_single_file(src: Path, dst: Path | None, tags: set[int] | None) -> None:
    raw = src.read_bytes()
    out, was_binlog, corrupt = maybe_decode_file(src.name, raw, tags)
    if was_binlog:
        note = f" -- {corrupt} corrupt record(s) skipped" if corrupt else ""
        print(f"decoded {src.name}: {len(raw)} -> {len(out)} bytes{note}", file=sys.stderr)
    else:
        print(f"{src.name} is not binlog-framed -- passed through unchanged", file=sys.stderr)

    if dst is None:
        sys.stdout.buffer.write(out)
    else:
        dst.write_bytes(out)
        print(f"wrote {dst}", file=sys.stderr)


def list_tags(src: Path) -> None:
    """--list-tags: report which topics are actually present in a file/zip
    and how many records each has, so you know what's worth filtering to
    before picking --tag values."""
    counts: dict[int, int] = {}

    def scan(data: bytes) -> None:
        inner, _ = _maybe_gunzip(data)
        records, _ = decode_records(inner)
        for tag, _ in records:
            counts[tag] = counts.get(tag, 0) + 1

    if zipfile.is_zipfile(src):
        with zipfile.ZipFile(src) as z:
            for info in z.infolist():
                scan(z.read(info.filename))
    else:
        scan(src.read_bytes())

    if not counts:
        print("no binlog-framed records found", file=sys.stderr)
        return
    for tag in sorted(counts, key=lambda t: -counts[t]):
        name = TAG_NAMES.get(tag, f"unknown-{tag}")
        print(f"{name}\t{counts[tag]} record(s)")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input", type=Path, help="a .zip (Share Logs bundle) or a single log file")
    ap.add_argument("-o", "--output", type=Path, default=None,
                     help="output path (dir/zip for a zip input, file for a single-file input); "
                          "default: <input>.decoded.zip next to a zip, or stdout for a single file")
    ap.add_argument("--tag", action="append", default=None, metavar="TOPIC",
                     help=f"only include records with this topic (repeatable). "
                          f"Choices: {', '.join(sorted(TAG_NAME_TO_ID))}. Default: all topics.")
    ap.add_argument("--list-tags", action="store_true",
                     help="instead of decoding, report which topics are present and their record counts")
    args = ap.parse_args()

    if not args.input.exists():
        print(f"error: {args.input} not found", file=sys.stderr)
        return 1

    if args.list_tags:
        list_tags(args.input)
        return 0

    tags: set[int] | None = None
    if args.tag:
        tags = set()
        for name in args.tag:
            if name not in TAG_NAME_TO_ID:
                print(f"error: unknown --tag {name!r}. Choices: {', '.join(sorted(TAG_NAME_TO_ID))}", file=sys.stderr)
                return 1
            tags.add(TAG_NAME_TO_ID[name])

    if zipfile.is_zipfile(args.input):
        dst = args.output or args.input.with_suffix("").with_suffix(".decoded.zip")
        process_zip(args.input, dst, tags)
    else:
        process_single_file(args.input, args.output, tags)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
