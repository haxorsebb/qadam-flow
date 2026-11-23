import { FederatedIdentityProvider } from '@aiqadam/shared'
import { FastifyBaseLogger } from 'fastify'
import { distributedLock } from '../../database/redis-connections'
import { platformRepo } from '../../platform/platform.service'
import { userFederatedIdentityService } from '../federated-identity/user-federated-identity-service'
import { systemGroupService } from './system-group-service'

// Periodic reconciliation applies revocations without waiting for the user to
// sign in. LDAP has its own directory-specific lifecycle, but both providers
// use the same Qadam grant writer.
export const systemReconcileService = (log: FastifyBaseLogger) => ({
    async reconcileAllPlatforms(): Promise<void> {
        if (process.env.AP_SYSTEM_AUTH_ENABLED !== 'true') return
        const groups = systemGroupService(log)
        const marked = await groups.listMarkedGroups()
        if (marked === null) {
            log.error('SYSTEM marker lookup failed; preserving existing grants')
            return
        }
        for (const platform of await platformRepo().find()) {
            try {
                await distributedLock(log).runExclusive({
                    key: `system-reconcile:${platform.id}`,
                    timeoutInSeconds: 60,
                    fn: async () => {
                        // Projects must be visible even before a marked-group
                        // member logs in for the first time.
                        await groups.ensureMarkedTeamProjects({ platformId: platform.id, marked })
                        const identities = await userFederatedIdentityService(log).listByPlatformAndProvider({
                            platformId: platform.id,
                            provider: FederatedIdentityProvider.SYSTEM,
                        })
                        for (const identity of identities) {
                            try {
                                const memberships = await groups.listUserGroups(identity.subject)
                                // An NSS outage is not the same as zero memberships.
                                if (memberships === null) continue
                                await groups.reconcileUser({
                                    platformId: platform.id,
                                    userId: identity.userId,
                                    groups: memberships,
                                    marked,
                                })
                            }
                            catch (err) {
                                log.error({ err, userId: identity.userId }, 'SYSTEM user grant reconciliation failed')
                            }
                        }
                    },
                })
            }
            catch (err) {
                log.error({ err, platformId: platform.id }, 'SYSTEM platform reconciliation failed')
            }
        }
    },
})
