# Upgrade SHAuditer v1.1.6 to v1.1.7

1. Back up your working v1.1.6 source directory, `~/.local/share/SHAuditer/` and any client reports before upgrading.
2. Extract `SHAuditer-Professional-v1.1.7.zip` into a **new sibling directory**. Keep your existing v1.1.6 installation operational for rollback. Do not merge an old `.venv`, database, local secrets or generated report folders into the release source.
3. Run `chmod +x install.sh SHAuditer SHAuditer-gui && ./install.sh`, then `./SHAuditer doctor`, `./SHAuditer tools --instructions`, and `./SHAuditer gui`.
4. New dashboard **Reports → NIST-aligned client & assessment details**: set actual client, authorization reference, test window and classification, save, and **regenerate** the PDF/DOCX/HTML reports. Scope and coverage are derived from audit records; do not claim unexecuted procedures.
5. If you want historic audits visible, **back up and re-use the existing `--home` directory** carefully. Use a copied home for the first compatibility check. Nothing in this new source ZIP overwrites your old workspaces automatically.
6. Optional Checkov and Gitleaks must be installed from audited official sources before they can run against expressly authorized local artifact directories with `--artifacts /path/to/project`. Catalog-only tools do not execute automatically.
7. Your Gmail credentials are not in the ZIP. On Kali Zsh, use the secure interactive `read -rs 'SHAUDITER_SMTP_PASSWORD?Gmail App Password: '` command and `export SHAUDITER_SMTP_PASSWORD`. The operator-confirmed configuration uses port 465 and `SHAUDITER_SMTP_SSL=true`; restart the *old running GUI* or use `Ctrl+C` to free port 8765 before starting this one.
8. Do not deliver confidential customer reports without inspecting their scope, evidence, redaction, recipients and confirmation. Test send to a self-controlled mailbox first.
9. Run `python3 -m pytest -q` and `node --check shauditer/gui/static/app.js` for release regression validation. See `docs/V117_RELEASE_AND_REPORTING.md`.

**Rollback:** stop the new GUI and start the original v1.1.6 installation from its preserved directory. This release is not a full enterprise multi-user SaaS product.

---

## Historical upgrade notes

# Upgrade SHAuditer v1.0.0 to v1.1.6

1. **Back up** your existing SHAuditer source directory and `~/.local/share/SHAuditer/` workspaces and `shauditer.db` before upgrading.
2. Extract the v1.1.6 ZIP to a **new sibling directory**. Do not overwrite a working v1.0 environment or merge `.venv`/reports into the upgraded source.
3. Execute `./install.sh`, then `./SHAuditer doctor`, `./SHAuditer tools --instructions`, and `./SHAuditer gui`.
4. Test an isolated local/authorized web application with `./SHAuditer --home /tmp/shauditer-v116-lab audit http://127.0.0.1:8000 --authorized` after starting an HTTP service yourself. Review missing tool status and report accuracy.
5. First run with a **copied** previous data home (`./SHAuditer --home /path/to/copied-old-home list`) rather than modifying your only copy. The SQLite schema remains compatible with prior assessments.
6. Optional scanner binaries are separate. Install from official distribution packages or verified upstream GitHub releases; the tool hub does **not** execute GitHub installer scripts.
7. To use email, configure `SHAUDITER_SMTP_HOST`, `SHAUDITER_SMTP_FROM`, `SHAUDITER_SMTP_PORT`, `SHAUDITER_SMTP_USER`, `SHAUDITER_SMTP_PASSWORD`, then restart the GUI. Explicitly confirm each recipient and send action. SMTP secrets are not in the ZIP or DB.
8. Read `docs/V116_FEATURES_AND_LIMITATIONS.md`; catalog-only tools are not promised working integrations, and no automated arbitrary exploit execution was introduced.

The prior installation remains intact for rollback. Never publish customer audit DBs or confidential report bundles in source repositories.


## Optional client-delivery revision of v1.1.6

The client-delivery ZIP is a drop-in source revision with unchanged application version and database schema. Install into a **new folder** rather than overwriting the previous release. Add `SHAUDITER_SMTP_DISPLAY_NAME` and optional `SHAUDITER_SMTP_REPLY_TO` to your team-controlled SMTP environment. Existing `mail` CLI calls still work; the new dashboard asks for current client contact, organization, a template and preview before sending. See `docs/CLIENT_DELIVERY_AND_EMAIL_TEMPLATES.md` for complete instructions and message templates.


## Street_Hackers Gmail sender upgrade (same application version)

The supplied team sender `streethackers03012026@gmail.com` is now selected by default in preview, CLI and the web console. Gmail SMTP uses `smtp.gmail.com:587` / STARTTLS; no mailbox password is stored. Enable 2-step verification and (if your account permits them) obtain a Google App Password; set it privately as `SHAUDITER_SMTP_PASSWORD` before starting the GUI. The app cannot deliver mail without an authorized SMTP credential. Always review the report and client recipient when switching engagements. Eight templates are available, with a factual summary of stored findings and coverage status. Read `docs/CLIENT_DELIVERY_AND_EMAIL_TEMPLATES.md` for details.
