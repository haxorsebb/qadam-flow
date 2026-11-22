import {
    AuthenticationResponse,
    FederatedIdentityProvider,
    UserIdentityProvider,
    ErrorCode,
    isNil,
    LdapTestStage,
    PlatformId,
    QadamFlowError,
    tryCatch,
    UserStatus,
} from '@aiqadam/shared'
import { FastifyBaseLogger } from 'fastify'
import { Entry } from 'ldapts'
import { authenticationUtils } from '../authentication-utils'
import { verifiedIdentityService } from '../verified-identity-service'
import { ldapAttributeUtils } from './ldap-attributes'
import { ldapClient } from './ldap-client'
import { ldapConfigService, ResolvedLdapConfig } from './ldap-config-service'
import { ldapGroupMappingService } from './ldap-group-mapping-service'
import { LdapStageError } from './ldap-stage-error'
import { ldapUsernameUtils } from './ldap-username'

// Fixed and directory-independent — built only from the platform's own configured `baseDn`, never
// from the caller-supplied username — so the dummy bind (below) carries no information of its own
// and every dummy attempt for a given platform targets the exact same, guaranteed-nonexistent DN.
const DUMMY_BIND_RDN = 'cn=__qadam_flow_timing_oracle_dummy_bind__'
const DUMMY_BIND_PASSWORD = 'qadam-flow-timing-oracle-defense'

export const ldapAuthnService = (log: FastifyBaseLogger) => ({
    async signIn({ platformId, username, password }: SignInParams): Promise<AuthenticationResponse> {
        // Refused before any lookup, config read, or network call — an empty password sent to an
        // unauthenticated ("simple", RFC 4513 §5.1.2) bind succeeds against most directories and
        // would otherwise let a caller who names a valid username skip authentication entirely.
        // The zod schema (`LdapSignInRequest.password.min(1)`) already refuses this at the HTTP
        // boundary; this repeats the check at the service boundary so the guarantee holds for any
        // future caller of this function directly, not only ones that go through the route.
        if (password.length === 0) {
            throw new QadamFlowError({ code: ErrorCode.INVALID_CREDENTIALS, params: null })
        }

        const resolved = await ldapConfigService(log).getResolvedForSignIn({ platformId })
        if (isNil(resolved) || !resolved.config.enabled) {
            throw new QadamFlowError({ code: ErrorCode.LDAP_DIRECTORY_UNREACHABLE, params: {} })
        }

        const { entry, subject, memberGroupDns } = await lookupDirectoryUser({ resolved, username, password, log })
        const email = ldapAttributeUtils.readStringAttribute({ entry, name: resolved.config.attributeMap.email })
        if (isNil(email) || email.length === 0) {
            throw new QadamFlowError({
                code: ErrorCode.LDAP_EMAIL_ATTRIBUTE_MISSING,
                params: { attribute: resolved.config.attributeMap.email },
            })
        }
        const firstName = ldapAttributeUtils.readStringAttribute({ entry, name: resolved.config.attributeMap.firstName }) ?? username
        const lastName = ldapAttributeUtils.readStringAttribute({ entry, name: resolved.config.attributeMap.lastName }) ?? ''

        const user = await verifiedIdentityService(log).resolveOrCreate({
            platformId,
            verified: {
                provider: FederatedIdentityProvider.LDAP,
                identityProvider: UserIdentityProvider.LDAP,
                subject,
                username,
                email,
                firstName,
                lastName,
                groups: memberGroupDns,
            },
            jitProvisioning: resolved.config.jitProvisioning,
            linkExistingByEmail: resolved.config.linkExistingByEmail,
        })
        if (user.status === UserStatus.INACTIVE) {
            throw new QadamFlowError({ code: ErrorCode.USER_IS_INACTIVE, params: { email } })
        }

        // Applied on every successful sign-in, after the user is guaranteed to exist (JIT or
        // otherwise) — never blocks the sign-in itself: a mapping problem here is a configuration
        // issue for an admin to fix, not a reason to refuse a directory account its own login.
        // `memberGroupDns === null` means group resolution itself already failed inside
        // `lookupDirectoryUser` (logged there) — skip applying the mapping entirely rather than
        // calling it with an empty group list, which would read as "this user is in no groups" and
        // strip every directory-managed project membership on a merely transient search error.
        if (!isNil(memberGroupDns)) {
            const { error: mappingError } = await tryCatch(() => ldapGroupMappingService(log).applyMapping({
                platformId,
                userId: user.id,
                config: resolved.config,
                memberGroupDns,
            }))
            if (!isNil(mappingError)) {
                log.error({ err: mappingError, platformId, userId: user.id }, '[ldapAuthnService] Failed to apply LDAP group mapping on sign-in')
            }
        }

        log.info({ platformId, userId: user.id }, 'User signed in via LDAP')
        return authenticationUtils(log).getProjectAndToken({
            userId: user.id,
            platformId,
            projectId: null,
            expiresInSeconds: resolved.config.sessionTtlSeconds,
        })
    },
})

// Service bind -> search -> user bind on a brand-new connection -> read attributes -> unbind, all
// against one already-decrypted config. Any failure inside is a `LdapStageError` (from
// `ldapClient`) or, once the subject attribute is checked, a plain misconfiguration signal — both
// are translated to one of the four public sign-in error codes by `mapToSignInError`, never leaked
// as their own stage-specific detail (that detail is what the admin-only `/test` endpoint is for).
async function lookupDirectoryUser({ resolved, username, password, log }: LookupDirectoryUserParams): Promise<{ entry: Entry, subject: string, memberGroupDns: string[] | null }> {
    const { config, bindPassword, connectionConfig } = resolved
    try {
        // The whole connect -> service bind -> search -> unbind sequence runs inside one
        // connection slot, held for its entire lifetime (M1) — the concurrency cap this slot
        // enforces is otherwise only a bound on simultaneous *connects*, not on how many
        // directory connections are actually open at once.
        const { entry, subject, memberGroupDns } = await ldapClient.withConnectionSlot(async () => {
            const client = await ldapClient.connect({ config: connectionConfig })
            try {
                await ldapClient.serviceBind({ client, bindDn: config.bindDn, bindPassword, tlsMode: config.tlsMode })
                // Normalised the same way, and for the same reason, the rate-limit bucket key is
                // (`ldapUsernameUtils.normalize`'s own comment) — a directory that folds Unicode
                // variants together (most do, since RFC 4515 says nothing about case- or
                // width-folding) must see the same value the rate limiter counted against.
                const entry = await ldapClient.searchForUser({
                    client,
                    baseDn: config.baseDn,
                    userFilter: config.userFilter,
                    username: ldapUsernameUtils.normalize(username),
                    attributeMap: config.attributeMap,
                    tlsMode: config.tlsMode,
                })
                const subject = ldapAttributeUtils.resolveSubject({ entry, attributeMap: config.attributeMap })
                if (isNil(subject) || subject.length === 0) {
                    log.error({ attribute: config.attributeMap.subject }, '[ldapAuthnService] Subject attribute missing or unreadable on the matched directory entry')
                    throw new LdapStageError({ stage: LdapTestStage.SEARCH, message: 'The configured subject attribute is missing on the matched entry' })
                }
                // Read on the same connection, before the service-bind connection is unbound — a
                // nested-group search (when configured) needs its own service-bound client, not the
                // user's own credentials. Deliberately its own try/catch, separate from the block
                // above: a broken group search (a bad `groupSearchFilter`, a directory that
                // temporarily can't answer it) must not fail the *sign-in* itself — `null` tells
                // the caller to skip applying the mapping this time rather than stripping
                // memberships over what is likely a transient or config error.
                const { data: memberGroupDns, error: groupError } = await tryCatch(() => ldapClient.resolveMemberGroupDns({ client, entry, config, tlsMode: config.tlsMode }))
                if (!isNil(groupError)) {
                    log.warn({ err: groupError, bindDn: config.bindDn }, '[ldapAuthnService] Group resolution failed; the sign-in proceeds without applying the LDAP group mapping this time')
                }
                return { entry, subject, memberGroupDns: isNil(groupError) ? memberGroupDns : null }
            }
            finally {
                await client.unbind().catch(() => undefined)
            }
        })
        await ldapClient.bindAsUser({ config: connectionConfig, userDn: entry.dn, password })
        return { entry, subject, memberGroupDns }
    }
    catch (error) {
        // Round 3: not just "no matching entry" (`notFound`) — a matched entry with a missing or
        // unreadable subject attribute (thrown just above) is the same timing residual: both bail
        // out after one connect+search, never reaching the second connect+bind a real
        // wrong-password case always pays for. Any `SEARCH`-stage failure shares that profile, so
        // the dummy bind covers the whole stage, not only the `notFound` case within it.
        if (error instanceof LdapStageError && error.stage === LdapTestStage.SEARCH) {
            await performDummyBind({ connectionConfig, baseDn: config.baseDn, log })
        }
        throw mapToSignInError(error)
    }
}

// Anti-timing-oracle (app-sec L2): without this, "unknown username" short-circuits after one
// connect+search, while "known username, wrong password" pays for a second connect+bind — a
// measurable latency gap that lets a caller enumerate valid usernames from response timing alone,
// even though both cases return the identical `INVALID_CREDENTIALS` body. Paying the same second
// connect+bind cost here closes that gap. The bind is expected to fail (there is no such DN) and
// its outcome — success or failure — is discarded either way; only the *cost* of attempting it
// matters.
async function performDummyBind({ connectionConfig, baseDn, log }: PerformDummyBindParams): Promise<void> {
    const { error } = await tryCatch(() => ldapClient.bindAsUser({
        config: connectionConfig,
        userDn: `${DUMMY_BIND_RDN},${baseDn}`,
        password: DUMMY_BIND_PASSWORD,
    }))
    if (!isNil(error)) {
        log.debug({ err: error }, '[ldapAuthnService] Dummy timing-oracle bind finished (a failure here is expected and harmless)')
    }
}

function mapToSignInError(error: unknown): QadamFlowError {
    if (!(error instanceof LdapStageError)) {
        return new QadamFlowError({ code: ErrorCode.LDAP_DIRECTORY_UNREACHABLE, params: {} })
    }
    switch (error.stage) {
        case LdapTestStage.ALLOW_LIST:
        case LdapTestStage.CONNECT:
            return new QadamFlowError({ code: ErrorCode.LDAP_DIRECTORY_UNREACHABLE, params: {} })
        case LdapTestStage.SERVICE_BIND:
            return new QadamFlowError({ code: ErrorCode.LDAP_BIND_ACCOUNT_REJECTED, params: {} })
        case LdapTestStage.SEARCH:
        case LdapTestStage.USER_BIND:
        case LdapTestStage.SUCCESS:
        default:
            // Anti-enumeration: an unknown username and a known username with the wrong password
            // both land here, with the same message and status — a caller cannot tell "no such
            // directory entry" apart from "wrong password" from this response alone.
            return new QadamFlowError({ code: ErrorCode.INVALID_CREDENTIALS, params: null })
    }
}

type SignInParams = {
    platformId: PlatformId
    username: string
    password: string
}

type LookupDirectoryUserParams = {
    resolved: ResolvedLdapConfig
    username: string
    password: string
    log: FastifyBaseLogger
}

type PerformDummyBindParams = {
    connectionConfig: ResolvedLdapConfig['connectionConfig']
    baseDn: string
    log: FastifyBaseLogger
}

