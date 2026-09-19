# SandboxieIOC

A Windows console tool that runs an executable inside a Sandboxie sandbox and
collects **network / web indicators of compromise (IOCs)** URLs, IP
addresses, DNS queries (domains), TCP/UDP connections (`ip:port`) and
authentication evidence (credentials embedded in URLs).

The output is a JSON report plus a self-contained HTML dashboard (no server,
no external dependencies) that you can open directly in a browser.

## How it works

The tool drives Sandboxie's public `QSbieAPI` layer and, at runtime, talks to
the Sandboxie core (the `SbieDrv` driver and `SbieSvc` service):

1. Connects to the driver as a regular client (`CSbieAPI::Connect`;
   it does **not** become the session leader, which would require a
   Sandboxie-signed process);
2. Creates/reuses an analysis sandbox and enables the network traces
   (`NetFwTrace=*`, `DnsTrace=y`);
3. Enables the resource monitor and clears the log;
4. Launches the sample with `RunStart`;
5. Waits for completion (or a timeout), terminating processes if needed;
6. Reads the trace (`GetTrace`) and extracts **network/web only**:
   - **DNS** → queried domains (`MONITOR_DNS` events);
   - **traffic** → IPs and `ip:port` + protocol (`MONITOR_NETFW` events,
     from the explicit `IPv4:`/`IPv6:` trace fields);
   - **URLs** → `http(s)://...` present in any trace message;
   - **authentication** → credentials in the `http://user:pass@host/` form;
7. Writes the JSON report and prints a summary;
8. Emits a self-contained HTML dashboard (`<output>.html`).

## Requirements

- Windows 7+ (64-bit) with **Sandboxie Plus** installed (driver + service
  running). The Classic edition works too.
- To build: **Qt (MinGW kit)** + MinGW-w64 (gcc). The prebuilt `QSbieAPI.dll`
  is MSVC-built, so this project compiles the QSbieAPI sources into the
  executable instead of linking against the DLL (same ABI, avoids the
  MSVC↔MinGW mismatch).

## Build

```
build.cmd
```

`build.cmd` invokes `qmake` + `mingw32-make` with the MinGW Qt kit. Adjust the
`QTDIR`/`MINGW` variables in `build.cmd` if your Qt install differs.

The executable is produced at `build-mingw\release\SandboxieIOC.exe`.

## Usage

```
SandboxieIOC.exe [options] <executable>

  -b, --box <name>       Sandbox to use (default: IOCAnalysis)
  -o, --output <file>    JSON report path (default: ioc_report.json)
  --timeout <sec>        Analysis timeout in seconds (default: 60)
  --block-network        Block internet/network access in the box
  --drop-admin           Enable DropAdminRights in the box
  --keep-box             Do not clean the sandbox after the analysis
```

Example:

```
SandboxieIOC.exe --timeout 90 C:\samples\malware.exe
```

## Output

Two files are written next to each other:

- `<output>.json` — machine-readable report;
- `<output>.html` — self-contained browser dashboard.

JSON structure:

```json
{
  "metadata":   { "sample", "box", "sandboxie_version", "date", "timeout_seconds", ... },
  "processes":  [ { "pid", "ppid", "name", "path", "cmdline" } ],
  "iocs": {
    "urls":           [ { "url": "http://..." } ],
    "ips":            [ { "ip": "a.b.c.d" } ],
    "domains":        [ { "name": "example.com", "pid": 123 } ],
    "connections":    [ { "endpoint": "ip:port", "ip", "port", "protocol", "pid" } ],
    "authentication": [ { "kind": "url_credentials", "evidence": "user:pass" } ]
  }
}
```

## Limitations / security

- Sandboxie records network activity at the **socket/DNS level**; it does not
  expose HTTP headers or payloads. "Authentication" is therefore limited to
  credentials visible in URLs/strings (e.g. basic-auth in a URL). Application
  level auth (form logins, cookies, `Authorization` headers) is **not**
  captured.
- HTTPS connections are reported by hostname (via DNS) and `ip:port`; the URL
  and payload of TLS traffic are not visible.
- Always run unknown samples in an isolated VM, never on a production host.

## License

This tool is distributed under the **GNU General Public License v3** (see
[LICENSE](LICENSE)). It compiles-in the LGPL `QSbieAPI` from
[Sandboxie](https://github.com/sandboxie-plus/Sandboxie) and drives the
Sandboxie core (GPLv3) at runtime.


