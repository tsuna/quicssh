#!/bin/bash
# Generate a self-signed certificate for testing quicssh

set -e

if [[ "$1" == "--help" || "$1" == "-h" ]]; then
    cat <<EOF
Usage: $0 [CERT_FILE] [KEY_FILE] [HOSTNAME]

Generate a self-signed TLS certificate for quicssh with SAN support.

Arguments:
  CERT_FILE   Path to certificate file (default: server.crt)
  KEY_FILE    Path to private key file (default: server.key)
  HOSTNAME    Hostname or IP address for the certificate (default: quicssh-server)
              If an IP address is provided, it will be added to the SAN IP list.

Examples:
  $0                                    # Generate server.crt/server.key for 'quicssh-server'
  $0 my.crt my.key example.com          # Generate for hostname 'example.com'
  $0 server.crt server.key 192.168.1.1  # Generate for IP address 192.168.1.1
EOF
    exit 0
fi

CERT_FILE="${1:-server.crt}"
KEY_FILE="${2:-server.key}"
HOSTNAME="${3:-quicssh-server}"

# Validate certificate file path
if [[ "$CERT_FILE" =~ [^a-zA-Z0-9._/-] ]]; then
    echo "Error: Invalid certificate file path: $CERT_FILE" >&2
    exit 1
fi

# Validate key file path
if [[ "$KEY_FILE" =~ [^a-zA-Z0-9._/-] ]]; then
    echo "Error: Invalid key file path: $KEY_FILE" >&2
    exit 1
fi

# Validate hostname/IP
# Allow: alphanumeric, dots, hyphens, colons (for IPv6), and underscores
if [[ ! "$HOSTNAME" =~ ^[a-zA-Z0-9._:-]+$ ]]; then
    echo "Error: Invalid hostname or IP address: $HOSTNAME" >&2
    echo "Hostname must contain only alphanumeric characters, dots, hyphens, colons, and underscores" >&2
    exit 1
fi

# Additional check: hostname shouldn't start or end with a dot or hyphen
if [[ "$HOSTNAME" =~ ^[.-] || "$HOSTNAME" =~ [.-]$ ]]; then
    echo "Error: Hostname cannot start or end with a dot or hyphen: $HOSTNAME" >&2
    exit 1
fi

echo "Generating self-signed certificate..."
echo "Certificate: $CERT_FILE"
echo "Private key: $KEY_FILE"
echo "Hostname/IP: $HOSTNAME"

# Create a config file for SAN (Subject Alternative Name)
CONFIG_FILE=$(mktemp)
trap "rm -f $CONFIG_FILE" EXIT

cat > "$CONFIG_FILE" <<EOF
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = $HOSTNAME
O = quicssh
C = US

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = $HOSTNAME
DNS.2 = localhost
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

# Add the hostname as IP if it looks like an IP address
if [[ "$HOSTNAME" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "IP.3 = $HOSTNAME" >> "$CONFIG_FILE"
elif [[ "$HOSTNAME" =~ ^[0-9a-fA-F:]+$ ]]; then
    echo "IP.3 = $HOSTNAME" >> "$CONFIG_FILE"
fi

openssl req -x509 -newkey rsa:4096 -keyout "$KEY_FILE" -out "$CERT_FILE" \
    -days 365 -nodes -config "$CONFIG_FILE"

echo ""
echo "Certificate generated successfully!"
echo ""
echo "Certificate details:"
openssl x509 -in "$CERT_FILE" -noout -text | grep -A1 "Subject Alternative Name"
echo ""
echo "Usage examples:"
echo ""
echo "Server (with certificate):"
echo "  quicssh server --bind 0.0.0.0:4242 --cert $CERT_FILE --key $KEY_FILE"
echo ""
echo "Client (with certificate verification):"
echo "  ssh -o ProxyCommand=\"quicssh client --addr %h:4242 --servercert $CERT_FILE\" user@hostname"
echo ""
echo "Or use insecure mode (not recommended for production):"
echo "  quicssh server --bind 0.0.0.0:4242 --insecure"
echo "  ssh -o ProxyCommand=\"quicssh client --addr %h:4242 --insecure\" user@hostname"

