# quicssh

> :smile: **quicssh** is a QUIC proxy that allows to use QUIC to connect to an SSH server without needing to patch the client or the server.

This is a substantial rewrite of [moul/quicssh](https://github.com/moul/quicssh), which appears to be abandoned and unmaintained. Key improvements include:

- **Session layer for connection resilience**: Transparent reconnection support that survives network changes, VPN switches, and even server IP changes
- **QUIC path migration**: Seamless handling of client IP changes (e.g., switching WiFi networks)
- **0-RTT resumption**: Fast reconnection using TLS 1.3 session resumption
- **Optimized data transfer**: Direct buffer writes, buffer pooling, and tuned QUIC flow control for better throughput
- **Automatic passthrough**: Bulk transfer tools (scp, rsync, sftp) automatically bypass QUIC for optimal performance
- **TLS certificate verification**: Proper certificate pinning with optional hostname verification skip for VPN scenarios
- **Updated dependencies**: Latest security patches and quic-go improvements

Originally based on improvements from [PR #178](https://github.com/moul/quicssh/pull/178).

## Architecture

Standard SSH connection

```
┌───────────────────────────────────────┐             ┌───────────────────────┐
│                  bob                  │             │         wopr          │
│ ┌───────────────────────────────────┐ │             │ ┌───────────────────┐ │
│ │           ssh user@wopr           │─┼────tcp──────┼▶│       sshd        │ │
│ └───────────────────────────────────┘ │             │ └───────────────────┘ │
└───────────────────────────────────────┘             └───────────────────────┘
```

---

SSH Connection proxified with QUIC

```
┌───────────────────────────────────────┐             ┌───────────────────────┐
│                  bob                  │             │         wopr          │
│ ┌───────────────────────────────────┐ │             │ ┌───────────────────┐ │
│ │ssh -o ProxyCommand="quicssh client│ │             │ │       sshd        │ │
│ │     --addr %h:4545" user@wopr     │ │             │ └───────────────────┘ │
│ │                                   │ │             │           ▲           │
│ └───────────────────────────────────┘ │             │           │           │
│                   │                   │             │           │           │
│                process                │             │  tcp to localhost:22  │
│                   │                   │             │           │           │
│                   ▼                   │             │           │           │
│ ┌───────────────────────────────────┐ │             │┌─────────────────────┐│
│ │  quicssh client --addr wopr:4545  │─┼─QUIC (udp)──▶│   quicssh server    ││
│ └───────────────────────────────────┘ │             │└─────────────────────┘│
└───────────────────────────────────────┘             └───────────────────────┘
```

## Install

```bash
# Install latest version
go install github.com/tsuna/quicssh@latest

# Install specific version
go install github.com/tsuna/quicssh@v1.1.0
```

Or download pre-built binaries from [releases](https://github.com/tsuna/quicssh/releases).

## Usage

### Quick Start (Insecure Mode)

For testing or trusted networks only:

```bash
# On the server
quicssh server --bind 0.0.0.0:4242 --insecure

# On the client
ssh -o ProxyCommand="quicssh client --addr %h:4242 --insecure" user@hostname
```

⚠️ **Warning**: Insecure mode skips TLS certificate verification and is vulnerable to man-in-the-middle attacks. Only use on trusted networks!

### Secure Mode (Recommended)

Generate a certificate:

```bash
./generate-cert.sh server.crt server.key
```

Or use your own certificate (e.g., from Let's Encrypt).

Start the server with the certificate:

```bash
quicssh server --bind 0.0.0.0:4242 --cert server.crt --key server.key
```

Connect with certificate verification:

```bash
# Copy server.crt to the client machine, then:
ssh -o ProxyCommand="quicssh client --addr %h:4242 --servercert server.crt" user@hostname
```

Or add to `~/.ssh/config`:

```
Host myserver
    ProxyCommand quicssh client --addr %h:4242 --servercert /path/to/server.crt
```

### Advanced Options

#### Server

```console
$ quicssh server -h
NAME:
   quicssh server

USAGE:
   quicssh server [command options]

OPTIONS:
   --bind value             bind address (default: "localhost:4242")
   --sshdaddr value         target address of sshd (default: "localhost:22")
   --idle-timeout value     QUIC idle timeout (ignored when --session-layer is enabled) (default: 30s)
   --insecure               generate and use self-signed certificate (insecure) (default: false)
   --cert value             path to TLS certificate file
   --key value              path to TLS private key file
   --verbose, -v            enable verbose logging (default: false)
   --session-layer          enable session layer for connection resilience (default: false)
   --session-timeout value  session timeout for reconnection (default: 30m0s)
   --max-sessions value     maximum number of concurrent sessions (0 = unlimited) (default: 1024)
   --buffer-size value      maximum size of send buffer per session in bytes (default: 16777216)
   --help, -h               show help
```

#### Client

```console
$ quicssh client -h
NAME:
   quicssh client

USAGE:
   quicssh client [command options]

OPTIONS:
   --addr value                 address of server (default: "localhost:4242")
   --localaddr value            source address of UDP packets (default: ":0")
   --idle-timeout value         QUIC idle timeout (ignored when --session-layer is enabled) (default: 30s)
   --insecure                   skip TLS certificate verification (insecure) (default: false)
   --servercert value           path to server's TLS certificate for verification
   --skip-verify-hostname       skip hostname verification (still verifies certificate) (default: false)
   --verbose, -v                enable verbose logging (default: false)
   --ssh-port value             SSH port for direct connection when bypassing QUIC (default: 22)
   --no-passthrough             disable automatic passthrough for bulk transfers (scp, rsync, sftp) (default: false)
   --path-check-interval value  interval for checking IP changes for path migration (0 to disable) (default: 10s)
   --session-layer              enable session layer for connection resilience (default: false)
   --buffer-size value          maximum size of send buffer per session in bytes (default: 16777216)
   --help, -h                   show help
```

### Examples

**Increase timeout for flaky VPN connections:**

```bash
# Server
quicssh server --bind 0.0.0.0:4242 --cert server.crt --key server.key --idletimeout 5m

# Client
ssh -o ProxyCommand="quicssh client --addr %h:4242 --servercert server.crt --idletimeout 5m" user@hostname
```

**NAT punching (specify source address):**

```bash
ssh -o ProxyCommand="quicssh client --addr %h:4242 --localaddr 192.168.1.100:0 --servercert server.crt" user@hostname
```

**Custom SSH daemon port:**

```bash
quicssh server --bind 0.0.0.0:4242 --sshdaddr localhost:2222 --cert server.crt --key server.key
```

**Certificate pinning without hostname verification (for proxies/VPNs):**

When connecting through a proxy or VPN that changes the server's IP address,
you can use `--skip-verify-hostname` to verify the certificate itself while
ignoring hostname/IP mismatches:

```bash
# Server is behind a proxy that assigns dynamic IPs
ssh -o ProxyCommand="quicssh client --addr 100.64.1.1:4242 --servercert server.crt --skip-verify-hostname" user@hostname
```

This still provides MITM protection through certificate pinning (the
certificate must match exactly), but doesn't verify that the hostname/IP
matches the certificate's SAN field.

## Session Layer

The session layer provides robust connection resilience that goes beyond what QUIC's native path migration can offer. Enable it with `--session-layer` on both client and server.

> **Note**: Both client and server must use `--session-layer` together, or both must not use it. A mismatch will result in a connection error.

### How It Works

1. **Session establishment**: When a client connects, it receives a unique session ID that persists across reconnections.

2. **Data buffering**: Both client and server maintain send buffers (default 16MB) with sequence numbers. Data is kept in the buffer until acknowledged.

3. **Transparent reconnection**: If the connection is lost, the client automatically reconnects and resumes the session:
    - Sends a `RESUME_SESSION` frame with the last sent/received sequence numbers
    - Server responds with `RESUME_ACK` containing its state
    - Both sides replay any unacknowledged data
    - The SSH session continues without interruption

4. **ACK piggybacking**: Instead of application-level ACKs, we hook into QUIC's internal packet acknowledgment mechanism for efficiency. This currently requires a [fork of quic-go](https://github.com/tsuna/quic-go) with a small patch to expose ACK callbacks.

### Resilience Scenarios

| Scenario                           | QUIC Path Migration | Session Layer   |
| ---------------------------------- | ------------------- | --------------- |
| Client IP changes (same server IP) | ✅ Seamless         | ✅ Seamless     |
| Brief network outage (<30s)        | ✅ Survives         | ✅ Survives     |
| Server IP changes (VPN switch)     | ❌ Connection lost  | ✅ Reconnects   |
| Long outage (>30s idle timeout)    | ❌ Connection lost  | ✅ Reconnects   |
| Process restart                    | ❌ Session lost     | ❌ Session lost |

### Example: VPN-Resilient SSH

```bash
# Server (with 5-minute session timeout)
quicssh server --bind 0.0.0.0:4242 --cert server.crt --key server.key \
    --session-layer --session-timeout 5m

# Client
ssh -o ProxyCommand="quicssh client --addr %h:4242 --servercert server.crt \
    --skip-verify-hostname --session-layer" user@hostname
```

With this configuration, you can:

- Disconnect from one VPN and connect to another
- Have the server's IP change (as seen by the client)
- Experience network outages up to the configured session timeout (e.g., hours or even days)
- Put your laptop to sleep and resume later
- All without losing your SSH session or any data

> **Tip**: When using `--session-layer`, consider adding `ServerAliveInterval 0` to your SSH client configuration (in `~/.ssh/config`) to prevent SSH from timing out during long idle periods. The session layer handles keepalives at the QUIC level, so SSH-level keepalives are unnecessary and can cause issues if they trigger during a network outage.

### Automatic Passthrough

For bulk transfer tools (scp, rsync, sftp), quicssh automatically detects when it's being spawned by these tools and bypasses QUIC entirely, connecting directly via TCP. This provides optimal performance for large file transfers while still benefiting from QUIC for interactive sessions.

Disable with `--no-passthrough` if you want all traffic to go through QUIC.

## Visual Studio Code Remote-SSH Integration

quicssh works great with VS Code's [Remote-SSH extension](https://code.visualstudio.com/docs/remote/ssh), but **you must patch the extension** to fully benefit from quicssh's connection resilience features.

### The Problem

VS Code Remote-SSH has two aggressive timeout values that cause it to abandon working connections ([see issue #11463](https://github.com/microsoft/vscode-remote-release/issues/11463)):

1. **ExecServerCache ping timeout (3 seconds)**: When VS Code tries to verify a cached connection is still alive, it only waits 3 seconds for a response.
2. **Local server dead man's switch (5 seconds)**: The local server process kills itself if it doesn't receive a keepalive within 5 seconds.

When your laptop sleeps and wakes up, the network stack needs time to recover. Even though quicssh keeps the underlying connection alive (thanks to QUIC's resilience and the session layer), VS Code gives up after just 3-5 seconds and tries to start a fresh connection—which often fails because the network hasn't fully recovered yet.

### The Solution

Run the `patch-vscode-remote-ssh` command to increase these timeouts to 25 hours:

```bash
quicssh patch-vscode-remote-ssh
```

This patches the VS Code Remote-SSH extension files in place, backing up the originals with a `.orig` extension. After patching, restart VS Code for the changes to take effect.

To restore the original files:

```bash
quicssh unpatch-vscode-remote-ssh
```

> **Note**: You will need to re-run `patch-vscode-remote-ssh` after VS Code updates the Remote-SSH extension.

### Recommended VS Code Configuration

For the best experience with quicssh, add these settings to your VS Code `settings.json`:

```json
{
    "remote.SSH.useLocalServer": true,
    "remote.SSH.showLoginTerminal": true
}
```

And in your `~/.ssh/config`, configure your host to use quicssh:

```
Host myserver
    ProxyCommand quicssh client --addr %h:4242 --servercert /path/to/server.crt --skip-verify-hostname --session-layer
```

With this setup and the patched extension, your VS Code remote sessions can survive:

- Laptop sleep/wake cycles (even hours or days)
- Network switches (WiFi to Ethernet, VPN changes)
- Brief network outages

## Performance

### Without Session Layer

When running without `--session-layer`, this fork includes optimizations for bulk data transfers:

- **Direct buffer writes**: Zero-copy data piping between QUIC streams and SSH connections
- **Buffer pooling**: Reuses 64KB buffers via `sync.Pool` to reduce GC pressure
- **Tuned QUIC flow control**: Larger receive windows for better throughput on high-latency links
- **Automatic passthrough**: Bulk transfers (scp, rsync, sftp) bypass QUIC for optimal TCP performance

### With Session Layer

The session layer trades some performance for resilience. Because data must be buffered until acknowledged (to enable replay after reconnection), there are additional memory copies on both client and server. This is an intentional tradeoff: you get the ability to survive network outages, VPN switches, and long idle periods, at the cost of some throughput.

For maximum throughput on large transfers, either:

- Don't use `--session-layer` (you still get QUIC path migration for client IP changes)
- Rely on automatic passthrough, which routes scp/rsync/sftp directly over TCP

Note: There is inherent overhead compared to direct SSH over TCP due to QUIC's userspace encryption and UDP packet handling.

## Security Considerations

- **TLS Encryption**: QUIC uses TLS 1.3 for encryption. Always use
  `--cert`/`--key` on the server and `--servercert` on the client for
  production.
- **SSH Layer**: SSH provides its own encryption and authentication on top of
  QUIC, so you get defense in depth.
- **Insecure Mode**: Only use `--insecure` for testing or on fully trusted
  networks. It's vulnerable to MITM attacks.
- **Certificate Verification**: The `--servercert` flag pins the server's
  certificate, preventing MITM attacks even if an attacker has a valid
  certificate.
- **Skip Hostname Verification**: The `--skip-verify-hostname` flag is useful
  when connecting through proxies or VPNs that change the server's IP
  address. It still verifies the certificate itself (certificate pinning),
  but skips checking if the hostname/IP matches the certificate's SAN field.
  This provides MITM protection while working with dynamic IPs.

## Troubleshooting

### Environment Variables

The following environment variables can be used to enable debug logging:

| Variable               | Values          | Description                                                                                                        |
| ---------------------- | --------------- | ------------------------------------------------------------------------------------------------------------------ |
| `QUICSSH_VERBOSE`      | `1`             | Enable verbose logging to stderr                                                                                   |
| `QUICSSH_VERBOSE`      | `/path/to/file` | Log to the specified file (useful for VS Code remote-ssh where stderr is not visible)                              |
| `QUICSSH_DEBUG_FRAMES` | `1`             | Enable per-frame debug logging with MD5 checksums and payload previews. Requires `QUICSSH_VERBOSE` to also be set. |

Example usage:

```bash
# Verbose logging to stderr
QUICSSH_VERBOSE=1 ssh -o ProxyCommand="quicssh client --addr %h:4242 --session-layer" user@host

# Log to a file (useful for debugging VS Code remote-ssh issues)
QUICSSH_VERBOSE=/tmp/quicssh.log ssh -o ProxyCommand="quicssh client --addr %h:4242 --session-layer" user@host

# Full frame-level debugging (very verbose)
QUICSSH_VERBOSE=1 QUICSSH_DEBUG_FRAMES=1 ssh -o ProxyCommand="quicssh client --addr %h:4242 --session-layer" user@host
```

### Signal Handlers

Both client and server support the following signals for runtime diagnostics:

| Signal      | Component | Description                                                        |
| ----------- | --------- | ------------------------------------------------------------------ |
| `SIGUSR1`   | Both      | Dump session statistics to stderr                                  |
| `SIGUSR2`   | Server    | Terminate all sessions inactive for more than 1 minute             |
| `SIGVTALRM` | Both      | Dump goroutine stack traces to stderr (useful for debugging hangs) |
| `SIGHUP`    | Server    | Reload TLS certificate                                             |

## Development

### Running Tests

Run all tests:

```bash
go test ./...
```

Run the end-to-end tests specifically:

```bash
go test -v -run TestE2E -timeout 60s .
```

The end-to-end tests use fake UDP transports (channel-based) instead of real network sockets, allowing the entire QUIC + session layer stack to be tested in a controlled environment without network dependencies. Key test files:

- `e2e_test.go`: End-to-end tests for basic connectivity and connection recovery
- `fake_transport_test.go`: Fake UDP transport infrastructure using Go channels

To run tests multiple times (useful for detecting race conditions or cleanup issues):

```bash
go test -v -run TestE2E -timeout 120s . -count 5
```

## Resources

- Original project: https://github.com/moul/quicssh
- https://korben.info/booster-ssh-quic-quicssh.html

## License

© 2019-2023 [Manfred Touron](https://manfred.life) - Original work
© 2025 [Benoît Sigoure](https://github.com/tsuna) - This fork

[Apache-2.0 License](https://github.com/moul/quicssh/blob/master/LICENSE)
