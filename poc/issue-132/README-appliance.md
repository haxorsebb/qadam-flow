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

## Marked SYSTEM groups and native TEAM projects

The non-login `qadam-group-marker` NSS identity is a member of every group
that the appliance grants Qadam access to. Its supplementary groups are the
authoritative allowlist; `qadam-users` is **not** hard-coded as the sole
eligibility group. The canonical platform owner remains exempt from the group
allowlist and is bound only by the trusted owner-bootstrap command.

For each marked group, Qadam creates a native TEAM project if none is linked.
It uses `system-group:gid:<numeric GID>` as the project `externalId` so
renaming a Unix group does not re-create the project. If an existing TEAM
project has exactly the group name and no `externalId`, it is associated with
that group; its name, project owner, data and administrator-selected roles
are otherwise left intact. A project already associated with a different
external group is not silently adopted.

Qadam's original platform owner is the creator/project ADMIN of newly created
TEAM projects. Ordinary users receive the native `Viewer` project role on
first synchronization. The marked group `qadam-admins` additionally promotes
the user's **platform** role to `ADMIN`. An external group may provide
project membership only; LDAP's explicit group-to-existing-project mappings
continue to work and now share the provenance-aware grant writer.

Synchronization runs during successful SYSTEM login and every minute through
the native system-job scheduler, including before anyone has logged in to see
newly marked TEAM projects. Removal from a marked group revokes only
SYSTEM-managed project memberships, not projects/workflows or separately
MANUAL/LDAP-managed membership rows. Administrators may adjust the role of
a SYSTEM-managed membership; the adjusted role survives further group sync
while membership remains valid, but is revoked if the external group is lost.
The same preservation rule is applied to LDAP-managed project membership
role edits.

A missing/failed NSS marker resolution does not strip existing grants.
New non-owner SYSTEM logins are refused when the marker cannot be read;
project-grant sync failures also prevent a fresh SYSTEM session from being
issued, rather than leaving unexpectedly stale permissions in place.
Existing bearer sessions and independent integration tokens need their own
revocation tests; this mechanism is **not** an instantaneous token revocation
system. SSSD/NSS caches may delay detection of changed group membership.

## POC regression plan

- Owner bootstrap succeeds once and subsequent runs refuse initialized data.
- Owner and ordinary user can authenticate with correct appliance passwords,
  but incorrect/locked/non-eligible users cannot obtain new sessions.
- With `qadam-group-marker` in `qadam-users` and `qadam-admins`, Qadam
  lists two distinct TEAM projects; the owner remains their project admin.
- A non-admin member of `qadam-users` sees the corresponding TEAM project
  with `Viewer` permissions, and no unrelated TEAM project.
- A member of `qadam-admins` receives the native platform ADMIN role.
- Adding a new marked group creates its TEAM project without user login.
- Raising a managed user's project role in the Qadam UI survives sync;
  removing the source group removes the managed membership, while separately
  MANUAL memberships remain.
- Verify scheduled revocation without a login, manual override preservation,
  LDAP group-mapping regression, persisted projects after reboot, and no
  database-migration drift.

