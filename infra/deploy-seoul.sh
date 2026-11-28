#!/usr/bin/env bash
set -euo pipefail

# Idempotent production deploy script for shouguatian.com on OpenCloudOS Server 9 / RHEL 9.
# Expects /etc/shougt/backend.env and /etc/nginx/ssl/shouguatian.{crt,key} to exist.

ENV_FILE="${SHOUGT_ENV_FILE:-/etc/shougt/backend.env}"
BACKEND_REPO="https://github.com/whoiswei114514/shougt-v0-backend.git"
FRONTEND_REPO="https://github.com/whoiswei114514/shougt-v4-frontend.git"
TRUST_REPO="https://github.com/whoiswei114514/shougt-fips-fido-trust.git"

BACKEND_DIR="/srv/gt/backend"
FRONTEND_DIR="/srv/gt/frontend"
FRONTEND_DIST="/srv/gt/frontend-dist"
TRUST_DIR="/srv/gt/fips-fido-trust"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "Missing $ENV_FILE" >&2
  exit 1
fi
if [[ ! -f /etc/nginx/ssl/shouguatian.crt || ! -f /etc/nginx/ssl/shouguatian.key ]]; then
  echo "Missing Nginx Origin SSL certificate in /etc/nginx/ssl/" >&2
  exit 1
fi

set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

export PATH="/usr/local/bin:/usr/local/node/bin:$PATH"

# 1. Ensure 2 GB swap so frontend builds never OOM on 2 GB RAM instances.
if ! swapon --show | grep -q '/swapfile'; then
  if [[ ! -f /swapfile ]]; then
    fallocate -l 2G /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=2048 status=none
    chmod 600 /swapfile
    mkswap /swapfile >/dev/null
  fi
  swapon /swapfile || true
  if ! grep -q '^/swapfile ' /etc/fstab; then
    echo '/swapfile none swap sw 0 0' >> /etc/fstab
  fi
fi

# 2. Install base packages and Python >= 3.11.
dnf install -y git curl ca-certificates nginx postgresql-server postgresql-devel redis gcc openssl-devel libffi-devel
if dnf list available python3.12 >/dev/null 2>&1; then
  dnf install -y python3.12 python3.12-devel python3.12-pip || dnf install -y python3.12 python3.12-devel
elif dnf list available python3.11 >/dev/null 2>&1; then
  dnf install -y python3.11 python3.11-devel python3.11-pip || dnf install -y python3.11 python3.11-devel
fi

pick_python() {
  for bin in /usr/local/bin/python3.12 python3.12 python3.11 python3; do
    if command -v "$bin" >/dev/null 2>&1; then
      if "$bin" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; then
        command -v "$bin"
        return 0
      fi
    fi
  done
  for uv_py in /root/.local/share/uv/python/cpython-3.12*/bin/python3.12; do
    if [[ -x "$uv_py" ]]; then
      echo "$uv_py"
      return 0
    fi
  done
  return 1
}

if ! PYTHON_BIN="$(pick_python)"; then
  curl -LsSf https://astral.sh/uv/install.sh | env UV_NO_MODIFY_PATH=1 sh
  export PATH="/root/.local/bin:$PATH"
  uv python install 3.12
  PYTHON_BIN="$(pick_python)"
fi
echo "Using Python: $PYTHON_BIN ($($PYTHON_BIN --version))"

if ! command -v npm >/dev/null 2>&1; then
  npm_bin="$(find /usr/local /opt /root -maxdepth 5 \( -type f -o -type l \) -name npm 2>/dev/null | head -n 1 || true)"
  if [[ -n "$npm_bin" ]]; then
    export PATH="$(dirname "$npm_bin"):$PATH"
  else
    dnf install -y nodejs npm
  fi
fi
echo "Using Node: $(node -v), npm: $(npm -v)"

# 3. Initialize & configure PostgreSQL and Redis.
if [[ ! -f /var/lib/pgsql/data/PG_VERSION ]]; then
  postgresql-setup --initdb
fi
PG_HBA="/var/lib/pgsql/data/pg_hba.conf"
if grep -qE '127\.0\.0\.1/32[[:space:]]+(ident|peer)' "$PG_HBA"; then
  sed -i -E 's#(127\.0\.0\.1/32[[:space:]]+)(ident|peer)#\1scram-sha-256#g' "$PG_HBA"
fi
if grep -qE '::1/128[[:space:]]+(ident|peer)' "$PG_HBA"; then
  sed -i -E 's#(::1/128[[:space:]]+)(ident|peer)#\1scram-sha-256#g' "$PG_HBA"
fi
systemctl enable --now postgresql redis

DB_NAME="${SHOUGT_DB_NAME:-gt}"
DB_USER="${SHOUGT_DB_USER:-srv}"
DB_PASS="${SHOUGT_DB_PASSWORD:?SHOUGT_DB_PASSWORD is required}"

su - postgres -c "psql -v ON_ERROR_STOP=1" <<SQL
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${DB_USER}') THEN
    EXECUTE format('CREATE ROLE %I WITH LOGIN PASSWORD %L', '${DB_USER}', '${DB_PASS}');
  ELSE
    EXECUTE format('ALTER ROLE %I WITH LOGIN PASSWORD %L', '${DB_USER}', '${DB_PASS}');
  END IF;
END
\$\$;
SQL
if ! su - postgres -c "psql -tAc \"SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'\"" | grep -qx '1'; then
  su - postgres -c "createdb -O '${DB_USER}' '${DB_NAME}'"
fi

# 4. Sync Git repositories.
mkdir -p /srv/gt /etc/shougt /var/log/shougt
sync_repo() {
  local url="$1" dest="$2"
  if [[ -d "$dest/.git" ]]; then
    git -C "$dest" fetch --prune origin
    git -C "$dest" checkout -B main origin/main
    git -C "$dest" reset --hard origin/main
  else
    git clone --branch main --depth 1 "$url" "$dest"
  fi
}
sync_repo "$BACKEND_REPO" "$BACKEND_DIR"
sync_repo "$FRONTEND_REPO" "$FRONTEND_DIR"
sync_repo "$TRUST_REPO" "$TRUST_DIR"

# 5. Python virtualenv & dependencies.
if [[ ! -x "$BACKEND_DIR/.venv/bin/python" ]]; then
  "$PYTHON_BIN" -m venv "$BACKEND_DIR/.venv"
fi
"$BACKEND_DIR/.venv/bin/python" -m pip install --upgrade pip wheel
"$BACKEND_DIR/.venv/bin/pip" install -r "$BACKEND_DIR/requirement.txt" gunicorn

# 6. Production config.yaml (non-secret; secrets stay in /etc/shougt/backend.env).
cat > "$BACKEND_DIR/config.yaml" <<'YAML'
mode: prod
allowed_hosts:
  - shouguatian.com
  - www.shouguatian.com
  - 127.0.0.1
  - localhost
education_email_suffixes: [edu.cn, edu, ac.uk]
education_institution_aliases: {}
default_from_email: noreply@shouguatian.com
material_review_contact: renzheng@shouguatian.com
webauthn_rp_id: shouguatian.com
webauthn_origins:
  - "https://shouguatian.com"
csrf_trusted_origins:
  - "https://shouguatian.com"
  - "https://www.shouguatian.com"
console_url: "https://privileged.shouguatian.com:18443"
email_provider: resend
resend_api_url: "https://api.resend.com/emails"
email_timeout: 15
captcha_required: false
fido_attestation_trust_files:
  - "/srv/gt/fips-fido-trust/data/shougt-fido-attestation-trust.json"
YAML
chmod 640 "$BACKEND_DIR/config.yaml"

# 7. Django check, migrate, collectstatic.
cd "$BACKEND_DIR"
"$BACKEND_DIR/.venv/bin/python" manage.py check
"$BACKEND_DIR/.venv/bin/python" manage.py migrate --noinput
"$BACKEND_DIR/.venv/bin/python" manage.py collectstatic --noinput

# 8. Build frontend & publish static dist.
cd "$FRONTEND_DIR"
npm ci --no-audit --no-fund
NODE_OPTIONS="--max-old-space-size=1536" npm run build
mkdir -p "$FRONTEND_DIST"
rm -rf "${FRONTEND_DIST:?}"/*
cp -a "$FRONTEND_DIR/dist/." "$FRONTEND_DIST/"
chmod 755 /srv /srv/gt "$FRONTEND_DIR" "$FRONTEND_DIST" "$BACKEND_DIR" "$BACKEND_DIR/staticfiles"

# 9. Automated FIPS + FIDO2+ trust bundle sync from GitHub Action output repo.
cat > /usr/local/bin/shougt-sync-fido-trust.sh <<'SYNC'
#!/usr/bin/env bash
set -euo pipefail
TRUST_DIR="/srv/gt/fips-fido-trust"
OLD_REV="$(git -C "$TRUST_DIR" rev-parse HEAD)"
git -C "$TRUST_DIR" fetch --prune origin
NEW_REV="$(git -C "$TRUST_DIR" rev-parse origin/main)"
if [[ "$OLD_REV" == "$NEW_REV" ]]; then
  echo "fips-fido-trust already at $OLD_REV"
  exit 0
fi
git -C "$TRUST_DIR" reset --hard origin/main
/srv/gt/backend/.venv/bin/python - <<'PY'
import json
from pathlib import Path
from cryptography import x509

trust_dir = Path("/srv/gt/fips-fido-trust")
items = json.loads((trust_dir / "data/shougt-fido-attestation-trust.json").read_text(encoding="utf-8"))
assert isinstance(items, list) and len(items) > 0
for item in items:
    p = trust_dir / item["root_pem"]
    x509.load_pem_x509_certificate(p.read_bytes())
print(f"Verified {len(items)} trust entries")
PY
systemctl reload-or-restart shougt-backend.service
echo "Updated fips-fido-trust: $OLD_REV -> $NEW_REV"
SYNC
chmod 750 /usr/local/bin/shougt-sync-fido-trust.sh

# 10. Systemd services & timer.
cat > /etc/systemd/system/shougt-backend.service <<'UNIT'
[Unit]
Description=shougt-v0-backend Gunicorn WSGI Service
After=network-online.target postgresql.service redis.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/srv/gt/backend
EnvironmentFile=/etc/shougt/backend.env
ExecStart=/srv/gt/backend/.venv/bin/gunicorn gt.wsgi:application --bind 127.0.0.1:18000 --workers 3 --threads 2 --timeout 60 --access-logfile /var/log/shougt/gunicorn-access.log --error-logfile /var/log/shougt/gunicorn-error.log
ExecReload=/bin/kill -s HUP $MAINPID
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT

cat > /etc/systemd/system/shougt-celery.service <<'UNIT'
[Unit]
Description=shougt-v0-backend Celery Worker
After=network-online.target postgresql.service redis.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/srv/gt/backend
EnvironmentFile=/etc/shougt/backend.env
ExecStart=/srv/gt/backend/.venv/bin/celery -A gt worker -l info --concurrency=2
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

cat > /etc/systemd/system/shougt-fido-trust-sync.service <<'UNIT'
[Unit]
Description=Sync shougt-fips-fido-trust attestation list
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/shougt-sync-fido-trust.sh
UNIT

cat > /etc/systemd/system/shougt-fido-trust-sync.timer <<'UNIT'
[Unit]
Description=Periodically sync NIST FIPS FIDO2+ trust certificates from GitHub

[Timer]
OnBootSec=5min
OnUnitActiveSec=6h
Persistent=true

[Install]
WantedBy=timers.target
UNIT

# 11. Nginx configuration (Cloudflare Origin SSL + SPA + /api/ reverse proxy).
if [[ -f /etc/nginx/nginx.conf && ! -f /etc/nginx/nginx.conf.orig ]]; then
  cp -a /etc/nginx/nginx.conf /etc/nginx/nginx.conf.orig
fi
cat > /etc/nginx/nginx.conf <<'NGINX_MAIN'
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log notice;
pid /run/nginx.pid;

include /usr/share/nginx/modules/*.conf;

events {
    worker_connections 1024;
}

http {
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';

    access_log /var/log/nginx/access.log main;

    sendfile on;
    tcp_nopush on;
    keepalive_timeout 65;
    types_hash_max_size 4096;
    client_max_body_size 64m;

    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    include /etc/nginx/conf.d/*.conf;
}
NGINX_MAIN

rm -f /etc/nginx/conf.d/default.conf
cat > /etc/nginx/conf.d/shouguatian.conf <<'NGINX_SITE'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name shouguatian.com www.shouguatian.com;
    return 301 https://shouguatian.com$request_uri;
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name www.shouguatian.com;

    ssl_certificate /etc/nginx/ssl/shouguatian.crt;
    ssl_certificate_key /etc/nginx/ssl/shouguatian.key;
    ssl_protocols TLSv1.2 TLSv1.3;

    return 301 https://shouguatian.com$request_uri;
}

server {
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    http2 on;
    server_name shouguatian.com;

    ssl_certificate /etc/nginx/ssl/shouguatian.crt;
    ssl_certificate_key /etc/nginx/ssl/shouguatian.key;
    ssl_protocols TLSv1.2 TLSv1.3;

    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    location /api/ {
        proxy_pass http://127.0.0.1:18000/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 60s;
    }

    location /django-admin/ {
        proxy_pass http://127.0.0.1:18000/django-admin/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 60s;
    }

    location /static/ {
        alias /srv/gt/backend/staticfiles/;
        expires 7d;
        add_header Cache-Control "public, immutable";
    }

    location / {
        root /srv/gt/frontend-dist;
        index index.html;
        try_files $uri $uri/ /index.html;
    }
}
NGINX_SITE

if command -v getenforce >/dev/null 2>&1 && [[ "$(getenforce)" == "Enforcing" ]]; then
  setsebool -P httpd_can_network_connect 1 || true
  chcon -R -t httpd_sys_content_t "$FRONTEND_DIST" "$BACKEND_DIR/staticfiles" || true
  chcon -R -t cert_t /etc/nginx/ssl || true
fi

nginx -t
systemctl daemon-reload
systemctl enable --now shougt-backend.service shougt-celery.service shougt-fido-trust-sync.timer nginx.service
systemctl restart shougt-backend.service shougt-celery.service nginx.service
echo "Deploy script completed."
