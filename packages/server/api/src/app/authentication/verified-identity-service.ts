import { cryptoUtils } from '@aiqadam/server-utils'
import {
    ErrorCode,
    FederatedIdentityProvider,
    isNil,
    PlatformId,
    PlatformRole,
    QadamFlowError,
    User,
    UserIdentity,
    UserIdentityProvider,
} from '@aiqadam/shared'
import { FastifyBaseLogger } from 'fastify'
import { EntityManager } from 'typeorm'
import { transaction } from '../core/db/transaction'
import { platformService } from '../platform/platform.service'
import { userService } from '../user/user-service'
import { userFederatedIdentityService } from './federated-identity/user-federated-identity-service'
import { userIdentityService } from './user-identity/user-identity-service'

// Authentication providers verify a password/token and resolve a canonical subject *before*
// calling this service. Neither JIT nor sessions accept an unauthenticated username.
export type VerifiedIdentity = {
    provider: FederatedIdentityProvider
    identityProvider: UserIdentityProvider
    subject: string
    username: string
    email: string
    firstName: string
    lastName: string
    groups: string[] | null
}

export const verifiedIdentityService = (log: FastifyBaseLogger) => ({
    async resolveOrCreate({ platformId, verified, jitProvisioning, linkExistingByEmail }: ResolveParams): Promise<User> {
        const bySubject = await userFederatedIdentityService(log).findBySubject({
            platformId,
            provider: verified.provider,
            subject: verified.subject,
        })
        if (!isNil(bySubject)) {
            return userService(log).getOrThrow({ id: bySubject.userId })
        }

        const identity = await userIdentityService(log).getIdentityByEmail(verified.email)
        if (!isNil(identity)) {
            return resolveExistingIdentity({ platformId, verified, identity, linkExistingByEmail, log })
        }
        if (!jitProvisioning) {
            throw new QadamFlowError({ code: ErrorCode.INVALID_CREDENTIALS, params: null })
        }

        // Identity, personal project and federated subject are persisted atomically.
        return transaction((entityManager) => provisionNewUser({
            platformId, verified, log, entityManager,
        }))
    },
})

async function resolveExistingIdentity({ platformId, verified, identity, linkExistingByEmail, log }: ResolveExistingParams): Promise<User> {
    // Never let an email collision claim a platform owner/admin or a different platform's account.
    const platform = await platformService(log).getOneOrThrow(platformId)
    const existingUsers = await userService(log).getByIdentityId({ identityId: identity.id })
    const isPrivilegedOrOwner = existingUsers.some((user) => user.platformRole === PlatformRole.ADMIN || user.id === platform.ownerId)
    const isCrossPlatform = existingUsers.some((user) => !isNil(user.platformId) && user.platformId !== platformId)
    if (isPrivilegedOrOwner || isCrossPlatform) {
        throw collision(identity.email)
    }

    if (identity.provider !== verified.identityProvider) {
        // The LDAP-only, owner-protected linking policy is preserved. SYSTEM never
        // takes over an existing local/LDAP user on the strength of an email match.
        if (!linkExistingByEmail || verified.provider !== FederatedIdentityProvider.LDAP) {
            throw collision(identity.email)
        }
        return transaction(async (entityManager) => {
            await userIdentityService(log).linkToFederatedProvider({
                id: identity.id, provider: verified.identityProvider, entityManager,
            })
            const user = await userService(log).getOrCreateWithProject({ identity, platformId, entityManager })
            await userFederatedIdentityService(log).create({
                platformId, userId: user.id, provider: verified.provider, subject: verified.subject, entityManager,
            })
            log.info({ platformId, userId: user.id }, 'Linked existing user to verified identity provider')
            return user
        })
    }

    // Recover a same-provider user whose federated link was lost. A changed subject
    // for the same identity is a collision, not an automatic account reassignment.
    return transaction(async (entityManager) => {
        const user = await userService(log).getOrCreateWithProject({ identity, platformId, entityManager })
        const linked = await userFederatedIdentityService(log).findByUser({
            platformId, userId: user.id, provider: verified.provider, entityManager,
        })
        if (!isNil(linked) && linked.subject !== verified.subject) {
            throw collision(identity.email)
        }
        if (isNil(linked)) {
            await userFederatedIdentityService(log).create({
                platformId, userId: user.id, provider: verified.provider, subject: verified.subject, entityManager,
            })
        }
        return user
    })
}

async function provisionNewUser({ platformId, verified, log, entityManager }: ProvisionParams): Promise<User> {
    const identity: UserIdentity = await userIdentityService(log).create({
        email: verified.email,
        firstName: verified.firstName,
        lastName: verified.lastName,
        password: await cryptoUtils.generateRandomPassword(),
        provider: verified.identityProvider,
        verified: true,
        trackEvents: false,
        newsLetter: false,
        entityManager,
    })
    const user = await userService(log).getOrCreateWithProject({ identity, platformId, entityManager })
    await userFederatedIdentityService(log).create({
        platformId, userId: user.id, provider: verified.provider, subject: verified.subject, entityManager,
    })
    log.info({ platformId, userId: user.id, provider: verified.provider }, 'JIT-provisioned verified identity')
    return user
}

function collision(email: string): QadamFlowError {
    return new QadamFlowError({ code: ErrorCode.LDAP_ACCOUNT_COLLISION, params: { email } })
}

type ResolveParams = {
    platformId: PlatformId
    verified: VerifiedIdentity
    jitProvisioning: boolean
    linkExistingByEmail: boolean
}
type ResolveExistingParams = {
    platformId: PlatformId
    verified: VerifiedIdentity
    identity: UserIdentity
    linkExistingByEmail: boolean
    log: FastifyBaseLogger
}
type ProvisionParams = {
    platformId: PlatformId
    verified: VerifiedIdentity
    log: FastifyBaseLogger
    entityManager: EntityManager
}
