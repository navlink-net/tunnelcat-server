#!/usr/bin/env bash
set -euo pipefail

AUTH_URL="https://squirrelwisdom.com"
LISTEN=":443"
LOG="/var/log/snc-exit.log"
CERT_DIR="/var/lib/snc-exit/certs"
BIN="$(cd "$(dirname "$0")" && pwd)/snc-exit"

# IP certificates require Certbot 5.4+.
CERTBOT_VERSION="$(certbot --version 2>&1 | grep -oP '\d+\.\d+' | head -1)"
CERTBOT_MAJOR="$(echo "$CERTBOT_VERSION" | cut -d. -f1)"
CERTBOT_MINOR="$(echo "$CERTBOT_VERSION" | cut -d. -f2)"
if [[ "$CERTBOT_MAJOR" -lt 5 ]] || [[ "$CERTBOT_MAJOR" -eq 5 && "$CERTBOT_MINOR" -lt 4 ]]; then
    echo "error: Certbot 5.4+ required for IP certificates (found $CERTBOT_VERSION)" >&2
    echo "       pip install --upgrade certbot" >&2
    exit 1
fi

# Determine the public IP of this machine.
PUBLIC_IP="$(ip -4 route get 1.1.1.1 | awk '{print $7; exit}')"
if [[ -z "$PUBLIC_IP" ]]; then
    echo "error: could not determine public IP" >&2
    exit 1
fi
echo "Public IP: $PUBLIC_IP"

CERT_PATH="/etc/letsencrypt/live/$PUBLIC_IP/fullchain.pem"
KEY_PATH="/etc/letsencrypt/live/$PUBLIC_IP/privkey.pem"

# Obtain or renew certificate.
# IP certificates are short-lived (160 h ≈ 6.7 days) — renewal runs every 12 h via cron.
# Port 80 must be free; snc-exit runs on 443 so no conflict.
certbot certonly \
    --standalone \
    --non-interactive \
    --agree-tos \
    --email kk@partners.solutions \
    --preferred-profile shortlived \
    --ip-address "$PUBLIC_IP"

mkdir -p "$CERT_DIR"

# Install renewal cron job (idempotent).
# Runs every 12 h; certbot skips renewal if cert still has plenty of time left.
# Deploy hook kills snc-exit so the restart loop below picks up the new cert.
CRON_LINE="0 */12 * * * certbot renew --quiet --deploy-hook 'pkill -f snc-exit' >> /var/log/snc-exit-renew.log 2>&1"
if ! crontab -l 2>/dev/null | grep -qF 'snc-exit-renew'; then
    (crontab -l 2>/dev/null; echo "$CRON_LINE") | crontab -
    echo "Renewal cron job installed (every 12 h)."
fi

# Run snc-exit in a restart loop.
# When certbot renews the cert it kills snc-exit via the deploy hook;
# the loop restarts it and the new process reads the updated cert files.
echo "Starting snc-exit (restart loop)..."
while true; do
    "$BIN" \
        --listen    "$LISTEN" \
        --auth-with "$AUTH_URL" \
        --tls-cert  "$CERT_PATH" \
        --tls-key   "$KEY_PATH" \
        --cert-dir  "$CERT_DIR" \
        --log       "$LOG" || true
    echo "$(date -u +%FT%TZ) snc-exit exited, restarting in 5s..." | tee -a "$LOG"
    sleep 5
done
