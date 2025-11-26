# quicssh

> :smile: **quicssh** is a QUIC proxy that allows to use QUIC to connect to an SSH server without needing to patch the client or the server.

This fork includes:

-   Updated dependencies with latest security patches
-   Optimized data transfer throughput for bulk operations (SCP, SFTP)
-   Configurable idle timeout for flaky connections
-   TLS certificate verification support and reloading certs at runtime
-   NAT punching support
-   Custom SSH daemon address

Based on [moul/quicssh](https://github.com/moul/quicssh) with improvements from [PR #178](https://github.com/moul/quicssh/pull/178)

This fork is intended to be used directly because upstream seems to have been
abandoned and is unmaintained.

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
│ │  quicssh client --addr wopr:4545  │─┼─quic (udp)──▶│   quicssh server    ││
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
   --bind value         bind address (default: "localhost:4242")
   --sshdaddr value     target address of sshd (default: "localhost:22")
   --idletimeout value  idle timeout (default: 30s)
   --insecure           generate and use self-signed certificate (insecure) (default: false)
   --cert value         path to TLS certificate file
   --key value          path to TLS private key file
   --help, -h           show help
```

#### Client

```console
$ quicssh client -h
NAME:
   quicssh client

USAGE:
   quicssh client [command options]

OPTIONS:
   --addr value              address of server (default: "localhost:4242")
   --localaddr value         source address of UDP packets (default: ":0")
   --idletimeout value       idle timeout (default: 30s)
   --insecure                skip TLS certificate verification (insecure) (default: false)
   --servercert value        path to server's TLS certificate for verification
   --skip-verify-hostname    skip hostname verification (still verifies certificate) (default: false)
   --help, -h                show help
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

## Performance

This fork includes optimizations for bulk data transfers (e.g., SCP, SFTP):

-   **Optimized data copying**: Direct buffer writes instead of intermediate
    copies
-   **Buffer pooling**: Reuses 64KB buffers via `sync.Pool` to reduce GC
    pressure
-   **Tuned QUIC flow control**: Larger receive windows (2MB initial, 16-32MB
    max) for better throughput on high-latency links

In benchmarks, these changes reduced allocations by ~99% and improved
throughput by ~20% for large transfers. Real-world SCP tests showed ~40%
faster transfers compared to the original implementation.

Note: There is still inherent overhead compared to direct SSH over TCP due to
QUIC's userspace encryption and UDP packet handling.

## Security Considerations

-   **TLS Encryption**: QUIC uses TLS 1.3 for encryption. Always use
    `--cert`/`--key` on the server and `--servercert` on the client for
    production.
-   **SSH Layer**: SSH provides its own encryption and authentication on top of
    QUIC, so you get defense in depth.
-   **Insecure Mode**: Only use `--insecure` for testing or on fully trusted
    networks. It's vulnerable to MITM attacks.
-   **Certificate Verification**: The `--servercert` flag pins the server's
    certificate, preventing MITM attacks even if an attacker has a valid
    certificate.
-   **Skip Hostname Verification**: The `--skip-verify-hostname` flag is useful
    when connecting through proxies or VPNs that change the server's IP
    address. It still verifies the certificate itself (certificate pinning),
    but skips checking if the hostname/IP matches the certificate's SAN field.
    This provides MITM protection while working with dynamic IPs.

## Resources

-   Original project: https://github.com/moul/quicssh
-   https://korben.info/booster-ssh-quic-quicssh.html

## License

© 2019-2023 [Manfred Touron](https://manfred.life) - Original work
© 2025 [Benoît Sigoure](https://github.com/tsuna) - This fork

[Apache-2.0 License](https://github.com/moul/quicssh/blob/master/LICENSE)
