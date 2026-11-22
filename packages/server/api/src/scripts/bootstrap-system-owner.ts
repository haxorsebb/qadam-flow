/* eslint-disable no-console */
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { cryptoUtils } from '@aiqadam/server-utils'
import { FederatedIdentityProvider, PlatformRole, ProjectType, UserIdentityProvider } from '@aiqadam/shared'
import { databaseConnection } from '../app/database/database-connection'
import { userFederatedIdentityService } from '../app/authentication/federated-identity/user-federated-identity-service'
import { userIdentityService } from '../app/authentication/user-identity/user-identity-service'
import { system } from '../app/helper/system/system'
import { platformService } from '../app/platform/platform.service'
import { projectService } from '../app/project/project-service'
import { userService } from '../app/user/user-service'

// Operator-only, one-shot provisioning. Not registered as an HTTP endpoint or
// invoked during normal API startup. Run from the APP container after migrations.
// This script never accepts a password or produces an authentication token.
async function main(): Promise<void> {
    if (process.env.AP_SYSTEM_AUTH_ENABLED !== 'true' || process.env.AP_CONTAINER_TYPE !== 'APP') {
        throw new Error('SYSTEM authentication must be enabled in an APP container')
    }

    const requestedUsername = process.env.AP_SYSTEM_AUTH_OWNER_USERNAME ?? 'administrator'
    if (!requestedUsername || requestedUsername.includes(':') || requestedUsername.includes('\n')) {
        throw new Error('Invalid SYSTEM owner username')
    }
    const { stdout } = await promisify(execFile)('getent', ['passwd', requestedUsername])
    const account = stdout.trim().split('\n')[0]?.split(':')
    if (!account || account.length < 7 || account[0] !== requestedUsername) {
        throw new Error('SYSTEM owner does not resolve to the required canonical NSS username')
    }
    const displayName = account[4]?.split(',')[0] || requestedUsername
    const log = system.globalLogger()
    const db = databaseConnection()

    // The APP must have already migrated its own database. Never let a
    // one-time provisioning command apply schema migrations implicitly.
    db.setOptions({ migrationsRun: false })
    await db.initialize()
    try {
        const result = await db.transaction(async (entityManager) => {
            // Serialize concurrent invocations before testing the empty-state
            // condition; every change below commits or rolls back as one unit.
            await entityManager.query('SELECT pg_advisory_xact_lock(132, 2026)')
            const [state] = await entityManager.query(`
                SELECT (SELECT count(*) FROM platform) AS platforms,
                       (SELECT count(*) FROM "user") AS users,
                       (SELECT count(*) FROM user_identity) AS identities,
                       (SELECT count(*) FROM user_federated_identity) AS federated_identities
            `)
            if (Object.values(state as Record<string, string>).some((count) => Number(count) !== 0)) {
                throw new Error('Refusing SYSTEM owner bootstrap: application identities or platforms already exist')
            }

            const identity = await userIdentityService(log).create({
                email: `${requestedUsername}@appliance.invalid`,
                firstName: displayName,
                lastName: '',
                password: await cryptoUtils.generateRandomPassword(),
                provider: UserIdentityProvider.SYSTEM,
                verified: true,
                trackEvents: false,
                newsLetter: false,
                entityManager,
            })
            const owner = await userService(log).create({
                identityId: identity.id,
                platformRole: PlatformRole.ADMIN,
                platformId: null,
                entityManager,
            })
            const platform = await platformService(log).create({
                ownerId: owner.id,
                name: 'Qadam Flow',
                entityManager,
            })
            await projectService(log).create({
                displayName: "Qadam Flow's Project",
                ownerId: owner.id,
                platformId: platform.id,
                type: ProjectType.PERSONAL,
                entityManager,
                callPostCreateHooks: false,
            })
            await userFederatedIdentityService(log).create({
                platformId: platform.id,
                userId: owner.id,
                provider: FederatedIdentityProvider.SYSTEM,
                subject: requestedUsername,
                entityManager,
            })
            return { platformId: platform.id, ownerId: owner.id }
        })
        console.log(`SYSTEM owner bootstrap succeeded: platform=${result.platformId} owner=${result.ownerId}`)
    }
    finally {
        await db.destroy()
    }
}

main().catch((error: unknown) => {
    console.error('SYSTEM owner bootstrap failed:', error)
    process.exitCode = 1
})
