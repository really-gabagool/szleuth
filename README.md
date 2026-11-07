# SZLEUTH

```
 ███████╗███████╗██╗     ███████╗██╗   ██╗████████╗██╗  ██╗
 ██╔════╝╚══███╔╝██║     ██╔════╝██║   ██║╚══██╔══╝██║  ██║
 ███████╗  ███╔╝ ██║     █████╗  ██║   ██║   ██║   ███████║
 ╚════██║ ███╔╝  ██║     ██╔══╝  ██║   ██║   ██║   ██╔══██║
 ███████║███████╗███████╗███████╗╚██████╔╝   ██║   ██║  ██║
 ╚══════╝╚══════╝╚══════╝╚══════╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝
   s7comm / SZL asset enumerator   ·   read-only recon
```

**SZLEUTH** is a read-only asset-enumeration tool for Siemens S7 PLCs. It speaks
S7comm over ISO-on-TCP (RFC 1006, TCP/102), performs the COTP + S7 communication
setup handshake, and reads the device's diagnostic **System Status Lists (SZL)**
to fingerprint it: order number, hardware/firmware versions, CPU name, serial
number, plant designation, current operating state, protection level, and module
LED status.

It is a *sleuth* for **SZL** data — hence the name.

---

## ⚠️ Authorized use only

SZLEUTH touches industrial control systems. Point it **only** at devices you own
or are explicitly authorized (in writing/scope) to assess. Enumerating ICS/OT
equipment you don't control may be unlawful, and production OT networks can be
fragile. You are responsible for how you use this.

It is **read-only by design**: it issues only SZL diagnostic *reads*. It contains
no control functions — no CPU stop/start, no memory or output writes, no
exploitation of any CVE. It is an inventory/recon tool, not an attack tool.

---

## Features

- COTP + S7 setup handshake with configurable rack/slot (tries slots 2, 1, 0)
- Reads the common fingerprinting SZLs and decodes them to readable fields
- Current CPU operating state (RUN / STOP / STARTUP / HOLD / DEFECT)
- Protection level (configured, effective) and physical mode-selector position
- Module LED status (SF / INTF / EXTF faults, FRCE, battery fault, RUN/STOP)
- Queries the CPU's own directory of supported SZLs (`--szl-dir`)
- Reads any arbitrary SZL ad-hoc (`--szl ID[:INDEX]`)
- Multiple targets: single host, `host:port`, CIDR range, comma list, or `@file`
- Concurrent scanning, text / JSON / CSV output
- Pure Python 3 standard library — **no dependencies**

## Requirements

- Python 3.7+
- A UTF-8 terminal for the banner (Windows Terminal / PowerShell 7 are fine;
  legacy `cmd.exe` may need `chcp 65001`, or use `--no-banner`)

## Install

```bash
git clone https://github.com/really-gabagool/szleuth
cd szleuth
python3 szleuth.py --help
```

No `pip install` needed.

## Usage

```
python3 szleuth.py [options] <targets...>

targets:
  10.0.0.5                a single host
  10.0.0.5:102            host with explicit port
  10.0.0.0/24             a CIDR range
  plc1,plc2,plc3          a comma-separated list
  @targets.txt            a file with one target per line (# comments allowed)
```

### Examples

```bash
# Enumerate one PLC
python3 szleuth.py 10.0.0.5

# Sweep a subnet, 32 workers, write an inventory CSV
python3 szleuth.py 10.0.0.0/24 -w 32 --csv inventory.csv

# JSON for piping into jq (banner goes to stderr, so stdout stays clean)
python3 szleuth.py 10.0.0.5 --json | jq .

# Ask the CPU which SZLs it supports, then pull a couple directly
python3 szleuth.py 10.0.0.5 --szl-dir --szl 0x0037 --szl 0x0131:0x0001

# Force a specific CPU slot and shorten the timeout for a wide sweep
python3 szleuth.py 10.0.0.0/22 -s 1 -t 2 --json > scan.json
```

### Example output

```
 ███████╗███████╗██╗     ███████╗██╗   ██╗████████╗██╗  ██╗
 ██╔════╝╚══███╔╝██║     ██╔════╝██║   ██║╚══██╔══╝██║  ██║
 ███████╗  ███╔╝ ██║     █████╗  ██║   ██║   ██║   ███████║
 ╚════██║ ███╔╝  ██║     ██╔══╝  ██║   ██║   ██║   ██╔══██║
 ███████║███████╗███████╗███████╗╚██████╔╝   ██║   ██║  ██║
 ╚══════╝╚══════╝╚══════╝╚══════╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝
   s7comm / SZL asset enumerator   ·   read-only recon   v1.0
      

[+] 192.0.2.10:102  S7 responded (slot 2)
      module                 6ES7 315-2EH14-0AB0  (V3.2.8)
      basic hardware         6ES7 315-2EH14-0AB0
      basic firmware         V3.2.8
      plant / station name   SIMATIC 300(1)
      module name            CPU 315-2 PN/DP
      serial number          S C-X1U203456
      plant designation      LINE-A
      operating state        RUN
      protection (config)    none configured (no password)
      protection (effective) 1 - open (all functions)
      mode selector          RUN-P
      LEDs                   RUN=on, BAF (battery fault)=blink 2Hz

1/1 host(s) responded to S7.
```

The same host as a CSV row (`--csv -`):

```
host,port,reachable,slot,cpu_state,protection_configured,protection_effective,mode_selector,leds,module,basic_firmware,station_name,module_name,serial_number,plant_designation,error
192.0.2.10,102,True,2,RUN,none configured (no password),1 - open (all functions),RUN-P,RUN=on; BAF (battery fault)=blink 2Hz,6ES7 315-2EH14-0AB0  (V3.2.8),V3.2.8,SIMATIC 300(1),CPU 315-2 PN/DP,S C-X1U203456,LINE-A,
```

Asking the CPU which lists it supports, and pulling one directly
(`--szl-dir --szl 0x0131:0x0001`):

```
$ python3 szleuth.py 192.0.2.10 --szl-dir --szl 0x0131:0x0001
[+] 192.0.2.10:102  S7 responded (slot 2)
      module                 6ES7 315-2EH14-0AB0  (V3.2.8)
      ...
      supported SZLs         12 -> 0x0000 0x0011 0x001c 0x0074 0x0119 0x0124 0x0131 0x0132 0x0174 0x0232 0x0424 0x0a91
      SZL 0x0131:0x0001: 1 record(s)
        000100011400c0000000f0001388000005dc
```

> Example values are illustrative. `192.0.2.0/24` is a documentation range
> (RFC 5737), not a real device.

### Options

| Option | Description |
|---|---|
| `-p, --port` | Default port (102) |
| `-t, --timeout` | Connection/read timeout in seconds (5) |
| `-w, --workers` | Concurrent workers (16) |
| `-s, --slots` | Rack-0 CPU slots to try, in order (default `2,1,0`) |
| `--szl-dir` | Also read SZL `0x0000` — the CPU's list of supported SZLs |
| `--szl ID[:INDEX]` | Read an arbitrary SZL (repeatable), e.g. `--szl 0x0131:0x0001` |
| `--raw` | Include raw SZL hex in the output |
| `--json` | JSON output to stdout |
| `--csv PATH` | Also write results to a CSV file (`-` for stdout) |
| `--no-banner` | Suppress the banner |
| `--version` | Print version and exit |

## What it reads

| SZL ID | Index | Content |
|---|---|---|
| `0x0011` | `0x0000` | Module identification — order number (MlfB), hardware & firmware versions |
| `0x001C` | `0x0000` | Component identification — station/module name, serial number, plant designation |
| `0x0424` | `0x0000` | Current CPU operating mode (RUN / STOP / STARTUP / HOLD / DEFECT) |
| `0x0232` | `0x0004` | Protection level (configured & effective) and mode-selector position |
| `0x0074` | `0x0000` | Module LED status (SF, INTF, EXTF, RUN, STOP, FRCE, battery fault, …) |
| `0x0000` | `0x0000` | Directory of SZLs the CPU supports (with `--szl-dir`) |

Reads are issued defensively — a device that rejects a given SZL (common on
S7-1200/1500 for some lists) simply leaves that field blank instead of aborting
the host. If structured decoding fails, SZLEUTH falls back to extracting
printable strings from the response.

## Output formats

- **Text** (default): one block per host, decoded fields, readable at a glance.
  Only non-off LEDs are shown so faults stand out.
- **JSON** (`--json`): full nested structure, including custom SZL records and
  raw hex when `--raw` is set. Written to stdout; the banner goes to stderr.
- **CSV** (`--csv PATH`): one flat row per target for asset inventories
  (`host, port, reachable, slot, cpu_state, protection_*, mode_selector, leds,
  module, basic_firmware, station_name, module_name, serial_number,
  plant_designation, error`).

## Exit codes

| Code | Meaning |
|---|---|
| `0` | At least one host responded to S7 |
| `1` | No host responded |
| `2` | Argument / input error |

## How it works

1. **COTP Connection Request** (ISO 8073 over RFC 1006) with a destination TSAP
   encoding the rack/slot of the target CPU.
2. **S7 setup communication** to negotiate the PDU size.
3. **SZL reads** — S7 *userdata* requests (function group CPU, subfunction read
   SZL) for each list above, with the responses parsed into labeled fields.

All of this uses standard, documented S7 diagnostic functions — the same data
asset-discovery tools like Nmap's `s7-info` and PLCScan collect.

## License

Released under the MIT License — see [`LICENSE`](LICENSE).

## Disclaimer

Provided as-is, for legitimate asset management, security research, and
authorized testing. The author assumes no liability for misuse or for any damage
resulting from use of this tool.
