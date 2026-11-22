# Issue #132 — physical appliance SYSTEM-auth POC

This Compose project is a **disposable evaluation**, not part of the appliance's
release-owned runtime. Keep it separate from `runtime` and do not attach it to
the existing application database or queue.

## Authentication boundary

On the physical development appliance, combine `compose.yaml` and
`appliance.compose.yaml`. Only the APP container receives the host SSSD
responder socket directory; `/var/lib/sss/pipes/private` is shadowed with a
private tmpfs. Do not mount `/etc/shadow`, `/etc/sssd`, keytabs or n8n secrets.
The default stack binds its HTTP port to loopback only.

## First owner

The SYSTEM login endpoint intentionally **does not** claim the platform owner.
When the APP has completed its database migrations, an authorized operator
must explicitly provision the first owner *once*:

```sh
docker compose --env-file .env -f compose.yaml -f appliance.compose.yaml \
  exec -T app node packages/server/api/dist/src/scripts/bootstrap-system-owner.js
```

The command reads `AP_SYSTEM_AUTH_OWNER_USERNAME` (default:
`administrator`), verifies that it resolves to the same canonical NSS name,
and creates the SYSTEM user identity, platform owner, personal project and
federated subject link **in a single PostgreSQL transaction**. It does not take
or store the appliance password and does not create a session. It requires
`AP_SYSTEM_AUTH_ENABLED=true`, refuses existing application identities or
platforms, and uses a transaction-scoped advisory lock to serialize attempts.
It never migrates the database.

Repeat execution must fail without modifying existing accounts. After success,
authenticate through the normal Qadam SYSTEM login form using the appliance
password; PAM/SSSD validates the password and account eligibility.

## Evidence still needed

- Build the image containing the bootstrap command, then stage it on the target
- First bootstrap succeeds; second attempt refuses; DB owner, provider and
  project records all match
- Valid PAM login succeeds, wrong password fails, account/group revocation
  blocks new login
- Native password signup/login/reset cannot bypass SYSTEM mode
- No external Qadam exposure or target-side network pulls
