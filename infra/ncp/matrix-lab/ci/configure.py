"""Ephemeral synthetic configuration. Never print secrets."""
import os
import pathlib
import secrets

runtime = pathlib.Path(__file__).resolve().parent / 'runtime'
runtime.mkdir(mode=0o700, exist_ok=False)
secret = secrets.token_hex(32)
(runtime / 'registration.secret').write_text(secret)
config = f'''server_name: matrix.ci
public_baseurl: http://127.0.0.1:18008/
pid_file: /data/homeserver.pid
listeners:
  - port: 8008
    type: http
    tls: false
    bind_addresses: [0.0.0.0]
    x_forwarded: false
    resources:
      - names: [client]
        compress: false
federation_domain_whitelist: []
trusted_key_servers: []
enable_registration: false
enable_registration_without_verification: false
allow_guest_access: false
allow_public_rooms_without_auth: false
allow_public_rooms_over_federation: false
registration_shared_secret: "{secret}"
macaroon_secret_key: "{secrets.token_hex(32)}"
form_secret: "{secrets.token_hex(32)}"
signing_key_path: /data/matrix.ci.signing.key
report_stats: false
enable_metrics: false
log_config: /ci/log.config
redaction_retention_period: 0
retention:
  enabled: false
database:
  name: sqlite3
  args:
    database: /data/homeserver.db
media_store_path: /data/media_store
url_preview_enabled: false
'''
(runtime / 'homeserver.yaml').write_text(config)
for name in ['registration.secret', 'homeserver.yaml']:
    os.chmod(runtime / name, 0o600)
