import { execFile, spawn } from 'node:child_process'
import { promisify } from 'node:util'
import {
    AuthenticationResponse,
    ErrorCode,
    FederatedIdentityProvider,
    PlatformId,
    QadamFlowError,
    UserIdentityProvider,
    UserStatus,
} from '@aiqadam/shared'
import { FastifyBaseLogger } from 'fastify'
import { authenticationUtils } from '../authentication-utils'
import { userFederatedIdentityService } from '../federated-identity/user-federated-identity-service'
import { verifiedIdentityService } from '../verified-identity-service'
import { platformService } from '../../platform/platform.service'

const execFileAsync = promisify(execFile)
const SESSION_TTL_SECONDS = 3600

export const systemAuthnService = (log: FastifyBaseLogger) => ({
    async signIn({ platformId, username, password }: SignInParams): Promise<AuthenticationResponse> {
        if (process.env.AP_SYSTEM_AUTH_ENABLED !== 'true' || !username || !password) {
            throw invalidCredentials()
        }

        const account = await resolveAccount(username)
        if (account === null || !(await authenticatePam(account.username, password))) {
            throw invalidCredentials()
        }

        const groups = await resolveGroups(account.username)
        if (groups === null) {
            throw invalidCredentials()
        }

        const ownerUsername = process.env.AP_SYSTEM_AUTH_OWNER_USERNAME ?? 'administrator'
        const isOwner = account.username === ownerUsername
        const eligible = isOwner ||
            groups.includes(process.env.AP_SYSTEM_AUTH_USER_GROUP ?? 'qadam-users') ||
            groups.includes(process.env.AP_SYSTEM_AUTH_ADMIN_GROUP ?? 'qadam-admins')
        if (!eligible) {
            throw invalidCredentials()
        }

        // Platform ownership is assigned during initial appliance provisioning.
        // A subsequent login must NEVER claim the existing owner through a name/email match.
        if (isOwner) {
            const linked = await userFederatedIdentityService(log).findBySubject({
                platformId, provider: FederatedIdentityProvider.SYSTEM, subject: account.username,
            })
            const platform = await platformService(log).getOneOrThrow(platformId)
            if (linked === null || linked.userId !== platform.ownerId) {
                throw invalidCredentials()
            }
        }

        // Qadam stores email as a mandatory, unique profile attribute. A local account
        // without email uses a non-deliverable address; identity linking is by SYSTEM subject.
        const email = `${account.username}@appliance.invalid`
        const user = await verifiedIdentityService(log).resolveOrCreate({
            platformId,
            verified: {
                provider: FederatedIdentityProvider.SYSTEM,
                identityProvider: UserIdentityProvider.SYSTEM,
                subject: account.username,
                username: account.username,
                email,
                firstName: account.displayName,
                lastName: '',
                groups,
            },
            jitProvisioning: !isOwner,
            linkExistingByEmail: false,
        })
        if (user.status !== UserStatus.ACTIVE) {
            throw new QadamFlowError({ code: ErrorCode.USER_IS_INACTIVE, params: { email } })
        }

        log.info({ platformId, userId: user.id }, 'User signed in via system PAM')
        return authenticationUtils(log).getProjectAndToken({
            userId: user.id, platformId, projectId: null, expiresInSeconds: SESSION_TTL_SECONDS,
        })
    },
})

async function resolveAccount(username: string): Promise<{ username: string, displayName: string } | null> {
    try {
        const { stdout } = await execFileAsync('getent', ['passwd', username])
        const firstLine = stdout.trim().split('\n')[0]
        const fields = firstLine.split(':')
        if (fields.length < 7 || !fields[0]) return null
        const canonicalUsername = fields[0]
        const displayName = (fields[4] ?? '').split(',')[0] || canonicalUsername
        return { username: canonicalUsername, displayName }
    }
    catch {
        return null
    }
}

async function resolveGroups(username: string): Promise<string[] | null> {
    try {
        const { stdout } = await execFileAsync('id', ['-nG', username])
        return stdout.trim().split(/\s+/).filter(Boolean)
    }
    catch {
        return null
    }
}

async function authenticatePam(username: string, password: string): Promise<boolean> {
    return new Promise<boolean>((resolve) => {
        const child = spawn('pamtester', [
            process.env.AP_SYSTEM_AUTH_PAM_SERVICE ?? 'qadam',
            username, 'authenticate', 'acct_mgmt',
        ], { stdio: ['pipe', 'ignore', 'ignore'] })
        let settled = false
        const finish = (ok: boolean) => {
            if (settled) return
            settled = true
            resolve(ok)
        }
        child.on('error', () => finish(false))
        child.on('close', (code) => finish(code === 0))
        child.stdin.on('error', () => finish(false))
        child.stdin.end(`${password}\n`)
    })
}

function invalidCredentials(): QadamFlowError {
    return new QadamFlowError({ code: ErrorCode.INVALID_CREDENTIALS, params: null })
}

type SignInParams = {
    platformId: PlatformId
    username: string
    password: string
}
