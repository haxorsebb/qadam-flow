import { LdapConfig, PlatformId, ProjectMemberManagedBy, UserId } from '@aiqadam/shared'
import { FastifyBaseLogger } from 'fastify'
import { managedGroupGrantService } from '../managed-group-grant-service'
import { ldapGroupMappingUtils } from './ldap-group-mapping'

// LDAP remains responsible for DN parsing and configured group-to-project
// mappings. Native Qadam role and membership reconciliation is shared with
// other external identity providers, including appliance SYSTEM/PAM.
export const ldapGroupMappingService = (log: FastifyBaseLogger) => ({
    async applyMapping({ platformId, userId, config, memberGroupDns }: ApplyMappingParams): Promise<void> {
        const grants = ldapGroupMappingUtils.resolveGrants({
            groupMappings: config.groupMappings,
            memberGroupDns,
        })
        await managedGroupGrantService(log).apply({
            platformId,
            userId,
            managedBy: ProjectMemberManagedBy.LDAP,
            platformRole: grants.platformRole,
            projectRoles: grants.projectRoles,
        })
    },
})

type ApplyMappingParams = {
    platformId: PlatformId
    userId: UserId
    config: LdapConfig
    memberGroupDns: string[]
}
