#!/usr/bin/env python3
"""
SZLEUTH - Siemens S7 (S7comm / ISO-TSAP) asset enumeration tool.

Read-only fingerprinting of S7 PLCs. For each target it performs the
COTP connection + S7 communication setup handshake, then reads the
diagnostic System Status Lists (SZL) that identify the device:

  SZL 0x0011  module identification  -> order number (MlfB), HW/FW versions
  SZL 0x001C  component identification -> PLC name, serial no., plant ID, etc.

These are read-only diagnostic reads (the same data Nmap's s7-info and
PLCScan collect). The tool does NOT issue any control functions
(no CPU stop/start, no memory/output writes).

AUTHORIZED USE ONLY. Run this against PLCs you own or have explicit
written permission to assess. Enumerating industrial control systems
you do not control may be unlawful, and ICS/OT networks can be fragile.
"""

import argparse
import concurrent.futures as cf
import csv
import ipaddress
import json
import socket
import string
import sys

# ---------------------------------------------------------------------------
# Low-level transport
# ---------------------------------------------------------------------------

PRINTABLE = set(string.printable.encode("ascii")) - set(b"\t\n\r\x0b\x0c")

__version__ = "1.0"

BANNER = """
 ███████╗███████╗██╗     ███████╗██╗   ██╗████████╗██╗  ██╗
 ██╔════╝╚══███╔╝██║     ██╔════╝██║   ██║╚══██╔══╝██║  ██║
 ███████╗  ███╔╝ ██║     █████╗  ██║   ██║   ██║   ███████║
 ╚════██║ ███╔╝  ██║     ██╔══╝  ██║   ██║   ██║   ██╔══██║
 ███████║███████╗███████╗███████╗╚██████╔╝   ██║   ██║  ██║
 ╚══════╝╚══════╝╚══════╝╚══════╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝
   s7comm / SZL asset enumerator   ·   read-only recon   v{ver}
        authorized targets only — you own it or you have a scope
"""


def print_banner(file=sys.stderr):
    file.write(BANNER.format(ver=__version__) + "\n")


def _recv_exact(sock, count):
    buf = bytearray()
    while len(buf) < count:
        chunk = sock.recv(count - len(buf))
        if not chunk:
            raise EOFError(f"connection closed after {len(buf)}/{count} bytes")
        buf.extend(chunk)
    return bytes(buf)


def _recv_tpkt(sock):
    """Read one TPKT-framed message (RFC 1006)."""
    header = _recv_exact(sock, 4)
    if header[0:1] != b"\x03":
        raise ValueError(f"bad TPKT version: {header.hex()}")
    total = int.from_bytes(header[2:4], "big")
    if total < 4:
        raise ValueError(f"bad TPKT length: {total}")
    return header + _recv_exact(sock, total - 4)


def _tpkt(payload: bytes) -> bytes:
    return b"\x03\x00" + (len(payload) + 4).to_bytes(2, "big") + payload


# ---------------------------------------------------------------------------
# Request builders
# ---------------------------------------------------------------------------

def build_cotp_cr(rack: int, slot: int, conn_type: int = 0x01,
                  src_tsap: int = 0x0100) -> bytes:
    """COTP Connection Request. dst TSAP encodes connection type + rack/slot."""
    dst_tsap = ((conn_type & 0xFF) << 8) | (((rack & 0x7) << 5) | (slot & 0x1F))
    cotp = bytes([
        0x11, 0xE0,              # len, PDU type = CR
        0x00, 0x00,              # dst reference
        0x00, 0x14,              # src reference
        0x00,                    # class / options
        0xC1, 0x02, (src_tsap >> 8) & 0xFF, src_tsap & 0xFF,   # src TSAP
        0xC2, 0x02, (dst_tsap >> 8) & 0xFF, dst_tsap & 0xFF,   # dst TSAP
        0xC0, 0x01, 0x0A,        # TPDU size = 1024
    ])
    return _tpkt(cotp)


def build_s7_setup() -> bytes:
    """S7 'Setup communication' - negotiates PDU size / AMQ limits."""
    payload = bytes.fromhex(
        "02f080"                          # COTP DT (data)
        "32" "01" "0000" "0000"           # S7 hdr: proto, job, redid, pduref
        "0008" "0000"                     # param len 8, data len 0
        "f0" "00" "0001" "0001" "01e0"    # setup: func, 0, max amq(2x), pdu len
    )
    return _tpkt(payload)


def build_szl_read(szl_id: int, index: int = 0x0000, seq: int = 1) -> bytes:
    """S7 userdata request: read a System Status List (SZL)."""
    payload = bytes.fromhex(
        "02f080"                          # COTP DT
        "32" "07" "0000" "0000"           # S7 hdr: proto, userdata, redid, pduref
        "0008" "0008"                     # param len 8, data len 8
        "000112" "04" "11" "44"           # param head, len, method, read-SZL
        + f"{seq & 0xFF:02x}" + "00"      # sequence no, data-unit ref
        "ff" "09" "0004"                  # data: success, octet-str, len 4
        + f"{szl_id & 0xFFFF:04x}"        # SZL-ID
        + f"{index & 0xFFFF:04x}"         # SZL-index
    )
    return _tpkt(payload)


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------

def _s7_data_section(reply: bytes):
    """Return the data payload of an S7 TPKT reply, or None."""
    if len(reply) < 19 or reply[4:7] != b"\x02\xf0\x80":
        return None
    s7 = reply[7:]
    if not s7 or s7[0] != 0x32:
        return None
    rosctr = s7[1]
    param_len = int.from_bytes(s7[6:8], "big")
    data_len = int.from_bytes(s7[8:10], "big")
    hdr = 12 if rosctr == 0x03 else 10        # ack_data has 2 extra error bytes
    start = hdr + param_len
    return s7[start:start + data_len]


def parse_szl(data: bytes):
    """Parse an SZL data section into (return_code, szl_id, index, records)."""
    if not data or len(data) < 4:
        return None
    ret = data[0]
    if ret != 0xFF:               # 0x0a = item not available, etc.
        return {"return_code": ret, "records": []}
    body = data[4:]
    if len(body) < 8:
        return {"return_code": ret, "records": []}
    szl_id = int.from_bytes(body[0:2], "big")
    index = int.from_bytes(body[2:4], "big")
    rec_len = int.from_bytes(body[4:6], "big")
    rec_cnt = int.from_bytes(body[6:8], "big")
    recs = []
    off = 8
    for _ in range(rec_cnt):
        chunk = body[off:off + rec_len]
        if len(chunk) < rec_len or rec_len == 0:
            break
        recs.append(chunk)
        off += rec_len
    return {"return_code": ret, "szl_id": szl_id, "index": index,
            "rec_len": rec_len, "records": recs}


def _clean_str(raw: bytes) -> str:
    return raw.split(b"\x00", 1)[0].decode("ascii", "replace").strip()


# SZL 0x001C: component identification (index -> label)
_C_IDENT = {
    0x0001: "plant / station name",
    0x0002: "module name",
    0x0003: "plant designation",
    0x0004: "copyright",
    0x0005: "serial number",
    0x0007: "module type name",
    0x0008: "memory card serial",
    0x0009: "manufacturer / profile",
    0x000A: "OEM id",
    0x000B: "location designation",
}


def decode_component_ident(parsed) -> dict:
    out = {}
    for rec in parsed.get("records", []):
        if len(rec) < 3:
            continue
        idx = int.from_bytes(rec[0:2], "big")
        val = _clean_str(rec[2:])
        if val:
            out[_C_IDENT.get(idx, f"index 0x{idx:04x}")] = val
    return out


# SZL 0x0011: module identification (index -> label)
_M_IDENT = {
    0x0001: "module",
    0x0006: "basic hardware",
    0x0007: "basic firmware",
}


def _decode_version(rec: bytes) -> str:
    """Best-effort version from the trailing words of a 0x0011 record."""
    tail = rec[-4:]
    if len(tail) < 4:
        return ""
    v1, v2, v3, v4 = tail
    # Common Siemens encoding: 'V' marker then major/minor/patch
    if v1 in (ord("V"), 0x56):
        return f"V{v2}.{v3}.{v4}"
    return f"{v2}.{v3}.{v4}"


def decode_module_ident(parsed) -> dict:
    out = {}
    for rec in parsed.get("records", []):
        if len(rec) < 22:
            continue
        idx = int.from_bytes(rec[0:2], "big")
        mlfb = _clean_str(rec[2:22])     # order number (MlfB)
        ver = _decode_version(rec)
        label = _M_IDENT.get(idx, f"index 0x{idx:04x}")
        entry = mlfb
        if ver:
            entry = f"{mlfb}  ({ver})" if mlfb else ver
        if entry:
            out[label] = entry
    return out


# SZL 0x0424 index 0x0000: current operating mode (bzu-id).
# The state byte is the LSB of the mode word, i.e. record offset 3
# (snap7 reads it as Data[3]; the OPC &szl(424) path lands on the same byte).
_CPU_STATE = {
    0x00: "unknown",
    0x01: "STOP (firmware update)",
    0x02: "STOP (memory reset)",
    0x03: "STOP (self-initialization)",
    0x04: "STOP",
    0x05: "STARTUP (cold restart)",
    0x06: "STARTUP",
    0x07: "RESTART (warm)",
    0x08: "RUN",
    0x0A: "HOLD",
    0x0D: "DEFECT",
}


def decode_cpu_state(parsed) -> dict:
    recs = parsed.get("records", [])
    if not recs or len(recs[0]) < 4:
        return {}
    code = recs[0][3]
    return {"code": code, "state": _CPU_STATE.get(code, f"0x{code:02x} (unmapped)")}


# SZL 0x0232 index 0x0004: protection level, mode selector, checksums (S7-300/400).
# Record (each field is a big-endian word; value in the low byte):
#   [0:2] index  [2:4] level-by-selector  [4:6] configured  [6:8] effective  [8:10] selector
_PROT_LEVEL = {
    0: "none configured (no password)",
    1: "1 - open (all functions)",
    2: "2 - write-protected",
    3: "3 - read/write-protected",
}
_MODE_SEL = {0: "undefined", 1: "RUN", 2: "RUN-P", 3: "STOP", 4: "MRES"}


def decode_protection(parsed) -> dict:
    recs = parsed.get("records", [])
    if not recs or len(recs[0]) < 10:
        return {}
    r = recs[0]
    par, valid, sel = r[5], r[7], r[9]
    return {
        "configured_level": _PROT_LEVEL.get(par, str(par)),
        "effective_level": _PROT_LEVEL.get(valid, str(valid)),
        "mode_selector": _MODE_SEL.get(sel, str(sel)),
    }


# SZL 0x0074 index 0x0000: status of the module LEDs.
# Record: led-id (word) + led-state (byte) + blink (byte).
_LED_ID = {
    0x01: "SF (group error)",
    0x02: "INTF (internal fault)",
    0x03: "EXTF (external fault)",
    0x04: "RUN",
    0x05: "STOP",
    0x06: "FRCE (force active)",
    0x07: "CRST (cold restart)",
    0x08: "BAF (battery fault)",
    0x09: "USR",
    0x0B: "BUS1F",
    0x0C: "BUS2F",
    0x0D: "REDF (redundancy)",
    0x0E: "MSTR (master)",
    0x0F: "RACK0",
}
_LED_STATE = {0: "off", 1: "on", 2: "blink 2Hz", 3: "blink 0.5Hz"}


def decode_leds(parsed) -> dict:
    out = {}
    for rec in parsed.get("records", []):
        if len(rec) < 3:
            continue
        lid = int.from_bytes(rec[0:2], "big")
        out[_LED_ID.get(lid, f"LED 0x{lid:02x}")] = _LED_STATE.get(
            rec[2], f"0x{rec[2]:02x}")
    return out


# SZL 0x0000 index 0x0000: directory of SZL partial lists the CPU supports.
def decode_szl_dir(parsed) -> list:
    ids = []
    for rec in parsed.get("records", []):
        if len(rec) >= 2:
            ids.append(int.from_bytes(rec[0:2], "big"))
    return ids


def ascii_strings(reply: bytes, minlen: int = 4):
    """Fallback: printable runs, like the original script."""
    out, cur = [], bytearray()
    for b in reply:
        if b in PRINTABLE:
            cur.append(b)
        else:
            if len(cur) >= minlen:
                out.append(cur.decode("ascii", "replace"))
            cur = bytearray()
    if len(cur) >= minlen:
        out.append(cur.decode("ascii", "replace"))
    return out


# ---------------------------------------------------------------------------
# Per-target enumeration
# ---------------------------------------------------------------------------

def enumerate_target(host, port, slots, timeout, raw=False,
                     want_dir=False, customs=None):
    result = {"host": host, "port": port, "reachable": False}
    last_err = None
    customs = customs or []

    for slot in slots:
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                sock.settimeout(timeout)

                # 1. COTP connection request
                sock.sendall(build_cotp_cr(rack=0, slot=slot))
                cotp_reply = _recv_tpkt(sock)
                if len(cotp_reply) < 6 or cotp_reply[5] != 0xD0:   # CC confirm
                    last_err = f"no COTP confirm on slot {slot}"
                    continue

                result["reachable"] = True
                result["slot"] = slot

                # 2. S7 setup communication
                sock.sendall(build_s7_setup())
                _recv_tpkt(sock)

                # 3. SZL reads (read-only diagnostics)
                raw_blobs = {}

                def _read(szl_id, index, seq):
                    """Request one SZL; return (reply, parsed) or (None, None)."""
                    try:
                        sock.sendall(build_szl_read(szl_id, index, seq))
                        reply = _recv_tpkt(sock)
                        raw_blobs[f"szl_{szl_id:04x}_{index:04x}"] = reply.hex()
                        return reply, parse_szl(_s7_data_section(reply) or b"")
                    except (OSError, EOFError, ValueError):
                        return None, None

                mod, mp = _read(0x0011, 0x0000, 1)      # module identification
                comp, cp = _read(0x001C, 0x0000, 2)     # component identification
                _, sp = _read(0x0424, 0x0000, 3)        # current operating mode
                _, pp = _read(0x0232, 0x0004, 4)        # protection level

                info = {}
                if mp:
                    info.update(decode_module_ident(mp))
                if cp:
                    info.update(decode_component_ident(cp))
                if not info:
                    info["ascii_fallback"] = (ascii_strings(mod or b"")
                                              + ascii_strings(comp or b""))
                result["info"] = info

                _, lp = _read(0x0074, 0x0000, 5)        # module LED status

                if sp and sp.get("return_code") == 0xFF:
                    result["cpu_state"] = decode_cpu_state(sp)
                if pp and pp.get("return_code") == 0xFF:
                    result["protection"] = decode_protection(pp)
                if lp and lp.get("return_code") == 0xFF:
                    leds = decode_leds(lp)
                    if leds:
                        result["leds"] = leds

                if want_dir:
                    _, dp = _read(0x0000, 0x0000, 6)    # supported SZL directory
                    if dp and dp.get("return_code") == 0xFF:
                        result["szl_dir"] = [f"0x{i:04x}"
                                             for i in decode_szl_dir(dp)]

                seq = 7
                for sid, idx in customs:
                    _, xp = _read(sid, idx, seq)
                    seq += 1
                    if not xp:
                        continue
                    entry = {"return_code": xp.get("return_code")}
                    if xp.get("return_code") == 0xFF:
                        entry["records"] = [r.hex() for r in xp.get("records", [])]
                        entry["ascii"] = ascii_strings(
                            b"".join(xp.get("records", [])))
                    result.setdefault("custom_szl", {})[
                        f"0x{sid:04x}:0x{idx:04x}"] = entry

                if raw:
                    result["raw"] = raw_blobs
                return result

        except (OSError, EOFError, ValueError) as e:
            last_err = str(e)
            continue

    if not result["reachable"]:
        result["error"] = last_err or "no response"
    return result


# ---------------------------------------------------------------------------
# Target expansion + CLI
# ---------------------------------------------------------------------------

def expand_targets(tokens, default_port):
    out = []
    for tok in tokens:
        tok = tok.strip()
        if not tok:
            continue
        if tok.startswith("@"):
            with open(tok[1:], "r", encoding="utf-8") as fh:
                out.extend(expand_targets(
                    [ln for ln in fh.read().splitlines() if ln.strip()
                     and not ln.strip().startswith("#")],
                    default_port))
            continue
        if "/" in tok and ":" not in tok.rsplit("/", 1)[-1]:
            try:
                net = ipaddress.ip_network(tok, strict=False)
                out.extend((str(ip), default_port) for ip in net.hosts())
                continue
            except ValueError:
                pass
        host, _, p = tok.rpartition(":")
        if host and p.isdigit():
            out.append((host, int(p)))
        else:
            out.append((tok, default_port))
    return out


def format_text(r):
    lines = []
    tag = f"{r['host']}:{r['port']}"
    if not r.get("reachable"):
        return f"[-] {tag}  unreachable ({r.get('error', 'no response')})"
    lines.append(f"[+] {tag}  S7 responded (slot {r.get('slot')})")
    for k, v in r.get("info", {}).items():
        if k == "ascii_fallback":
            for s in v:
                lines.append(f"      ~ {s}")
        else:
            lines.append(f"      {k:<22} {v}")
    st = r.get("cpu_state")
    if st:
        lines.append(f"      {'operating state':<22} {st.get('state')}")
    pr = r.get("protection")
    if pr:
        lines.append(f"      {'protection (config)':<22} {pr.get('configured_level')}")
        lines.append(f"      {'protection (effective)':<22} {pr.get('effective_level')}")
        lines.append(f"      {'mode selector':<22} {pr.get('mode_selector')}")
    leds = r.get("leds")
    if leds:
        active = {k: v for k, v in leds.items() if v != "off"}
        shown = ", ".join(f"{k}={v}" for k, v in active.items()) \
            if active else "all nominal (off)"
        lines.append(f"      {'LEDs':<22} {shown}")
    d = r.get("szl_dir")
    if d:
        lines.append(f"      {'supported SZLs':<22} {len(d)} -> {' '.join(d)}")
    cs = r.get("custom_szl")
    if cs:
        for key, ent in cs.items():
            if ent.get("return_code") == 0xFF:
                recs = ent.get("records", [])
                lines.append(f"      SZL {key}: {len(recs)} record(s)")
                for h in recs:
                    lines.append(f"        {h}")
                if ent.get("ascii"):
                    lines.append("        ~ " + "  ".join(ent["ascii"]))
            else:
                rc = ent.get("return_code")
                rc_s = f"0x{rc:02x}" if rc is not None else "no reply"
                lines.append(f"      SZL {key}: no data ({rc_s})")
    return "\n".join(lines)


_CSV_COLS = [
    "host", "port", "reachable", "slot", "cpu_state",
    "protection_configured", "protection_effective", "mode_selector", "leds",
    "module", "basic_firmware", "station_name", "module_name",
    "serial_number", "plant_designation", "error",
]


def _csv_row(r):
    info = r.get("info") or {}
    st = r.get("cpu_state") or {}
    pr = r.get("protection") or {}
    return {
        "host": r.get("host", ""),
        "port": r.get("port", ""),
        "reachable": r.get("reachable", False),
        "slot": r.get("slot", ""),
        "cpu_state": st.get("state", ""),
        "protection_configured": pr.get("configured_level", ""),
        "protection_effective": pr.get("effective_level", ""),
        "mode_selector": pr.get("mode_selector", ""),
        "leds": "; ".join(f"{k}={v}" for k, v in (r.get("leds") or {}).items()
                          if v != "off"),
        "module": info.get("module", ""),
        "basic_firmware": info.get("basic firmware", ""),
        "station_name": info.get("plant / station name", ""),
        "module_name": info.get("module name", ""),
        "serial_number": info.get("serial number", ""),
        "plant_designation": info.get("plant designation", ""),
        "error": r.get("error", ""),
    }


def write_csv(results, path):
    fh = sys.stdout if path == "-" else open(path, "w", newline="", encoding="utf-8")
    try:
        writer = csv.DictWriter(fh, fieldnames=_CSV_COLS)
        writer.writeheader()
        for r in results:
            writer.writerow(_csv_row(r))
    finally:
        if fh is not sys.stdout:
            fh.close()


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="szleuth",
        description="SZLEUTH - read-only Siemens S7 asset enumeration "
                    "(authorized use only).",
        epilog="targets: host | host:port | 10.0.0.0/24 | @file.txt | comma list")
    ap.add_argument("--version", action="version",
                    version=f"SZLEUTH {__version__}")
    ap.add_argument("--no-banner", action="store_true", help="suppress the banner")
    ap.add_argument("targets", nargs="+", help="hosts / CIDRs / @file")
    ap.add_argument("-p", "--port", type=int, default=102, help="default port (102)")
    ap.add_argument("-t", "--timeout", type=float, default=5.0, help="seconds (5)")
    ap.add_argument("-w", "--workers", type=int, default=16, help="concurrency (16)")
    ap.add_argument("-s", "--slots", default="2,1,0",
                    help="rack-0 CPU slots to try, in order (default 2,1,0)")
    ap.add_argument("--szl-dir", action="store_true",
                    help="also read SZL 0x0000: the CPU's list of supported SZLs")
    ap.add_argument("--szl", action="append", metavar="ID[:INDEX]",
                    help="read an arbitrary SZL (repeatable), "
                         "e.g. --szl 0x0131:0x0001 --szl 0x0037")
    ap.add_argument("--raw", action="store_true", help="include raw SZL hex")
    ap.add_argument("--json", action="store_true", help="JSON output")
    ap.add_argument("--csv", metavar="PATH",
                    help="also write results to a CSV file ('-' for stdout)")
    args = ap.parse_args(argv)

    if not args.no_banner:
        print_banner()

    # commas in a single positional token -> split
    tokens = []
    for t in args.targets:
        tokens.extend(t.split(",") if "," in t else [t])

    try:
        targets = expand_targets(tokens, args.port)
    except OSError as e:
        print(f"error reading target file: {e}", file=sys.stderr)
        return 2

    slots = [int(x) for x in args.slots.split(",") if x.strip() != ""]

    def _parse_szl(tok):
        hi, _, lo = tok.partition(":")
        return int(hi, 0), (int(lo, 0) if lo else 0)

    try:
        customs = [_parse_szl(x) for x in (args.szl or [])]
    except ValueError:
        print("error: --szl expects ID[:INDEX], e.g. 0x0131:0x0001",
              file=sys.stderr)
        return 2

    results = []
    with cf.ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        futs = {pool.submit(enumerate_target, h, p, slots, args.timeout,
                            args.raw, args.szl_dir, customs): (h, p)
                for h, p in targets}
        for fut in cf.as_completed(futs):
            r = fut.result()
            results.append(r)
            if not args.json:
                print(format_text(r))

    if args.json:
        print(json.dumps(results, indent=2))

    if args.csv:
        try:
            write_csv(results, args.csv)
            if args.csv != "-":
                print(f"CSV written to {args.csv}", file=sys.stderr)
        except OSError as e:
            print(f"error writing CSV: {e}", file=sys.stderr)

    reachable = sum(1 for r in results if r.get("reachable"))
    if not args.json:
        print(f"\n{reachable}/{len(results)} host(s) responded to S7.",
              file=sys.stderr)
    return 0 if reachable else 1


if __name__ == "__main__":
    raise SystemExit(main())
