# SHAuditer v1.1.7 — Gmail SMTP compatibility hotfix

The `SHAUDITER_SMTP_SSL=true` option uses implicit TLS (SSL) on port 465. Gmail may disconnect during `AUTH` if Python sends an initial response. The login call now sets `initial_response_ok=False`, matching a successful standalone port 465 test.

## Kali Linux / Zsh

```zsh
export SHAUDITER_SMTP_HOST=smtp.gmail.com
export SHAUDITER_SMTP_PORT=465
export SHAUDITER_SMTP_SSL=true
export SHAUDITER_SMTP_USER=streethackers03012026@gmail.com
export SHAUDITER_SMTP_FROM=streethackers03012026@gmail.com
export SHAUDITER_SMTP_DISPLAY_NAME='Street_Hackers Security Team'
read -rs 'SHAUDITER_SMTP_PASSWORD?New Gmail App Password: '
echo
export SHAUDITER_SMTP_PASSWORD
./SHAuditer gui
```

First stop any prior process using port 8765. The App Password remains private and is not included in the ZIP.

This fix has local mocked SMTP tests, not a live Gmail-delivery guarantee.
