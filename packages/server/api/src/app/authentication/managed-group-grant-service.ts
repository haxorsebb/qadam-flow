import {
    apId, DefaultProjectRole, isNil, PlatformId, PlatformRole,
    PlatformRoleManagedBy, ProjectMemberManagedBy, ProjectType, UserId,
} from '@aiqadam/shared'
import { FastifyBaseLogger } from 'fastify'
import { In } from 'typeorm'
import { repoFactory } from '../core/db/repo-factory'
import { websocketService } from '../core/websockets.service'
import { platformService } from '../platform/platform.service'
import { ProjectMemberEntity } from '../project/project-member.entity'
import { projectService } from '../project/project-service'
import { userService } from '../user/user-service'

// Providers resolve their own group identities and mapping policy. This service
// owns the common, provenance-aware writes to Qadam's native authorization model.
const projectMemberRepo = repoFactory(ProjectMemberEntity)
type ManagedBy = ProjectMemberManagedBy.LDAP | ProjectMemberManagedBy.SYSTEM

const roleRank: Record<PlatformRole, number> = {
    [PlatformRole.MEMBER]: 0,
    [PlatformRole.OPERATOR]: 1,
    [PlatformRole.ADMIN]: 2,
}

export const managedGroupGrantService = (log: FastifyBaseLogger) => ({
    async apply({ platformId, userId, managedBy, platformRole, projectRoles }: ApplyParams): Promise<void> {
        await applyPlatformRole({ platformId, userId, managedBy, platformRole, log })
        await applyProjectMemberships({ platformId, userId, managedBy, projectRoles, log })
    },
})

async function applyPlatformRole({ platformId, userId, managedBy, platformRole, log }: ApplyPlatformParams): Promise<void> {
    const [platform, user] = await Promise.all([
        platformService(log).getOneOrThrow(platformId),
        userService(log).getOrThrow({ id: userId }),
    ])
    if (user.id === platform.ownerId) return

    const manual = user.platformRoleManagedBy === PlatformRoleManagedBy.MANUAL
    // Never take ownership of a role governed by another external provider.
    if (!manual && user.platformRoleManagedBy !== managedBy) return

    if (!isNil(platformRole)) {
        // Directory grants may promote manual roles, but never demote them.
        if (manual && roleRank[platformRole] <= roleRank[user.platformRole]) return
        if (user.platformRole === platformRole && user.platformRoleManagedBy === managedBy) return
        await userService(log).transitionPlatformRoleIfCurrentlyEquals({
            id: userId,
            platformId,
            expectedPlatformRole: user.platformRole,
            expectedPlatformRoleManagedBy: user.platformRoleManagedBy,
            newPlatformRole: platformRole,
            newPlatformRoleManagedBy: managedBy,
            newPlatformRoleManualBaseline: manual ? user.platformRole : (user.platformRoleManualBaseline ?? null),
        })
        return
    }

    if (manual) return
    const restoringManual = !isNil(user.platformRoleManualBaseline)
    const baseline = user.platformRoleManualBaseline ?? PlatformRole.MEMBER
    if (user.platformRole !== baseline || restoringManual) {
        await userService(log).transitionPlatformRoleIfCurrentlyEquals({
            id: userId,
            platformId,
            expectedPlatformRole: user.platformRole,
            expectedPlatformRoleManagedBy: managedBy,
            newPlatformRole: baseline,
            newPlatformRoleManagedBy: restoringManual ? PlatformRoleManagedBy.MANUAL : managedBy,
            newPlatformRoleManualBaseline: null,
        })
    }
}

async function applyProjectMemberships({ platformId, userId, managedBy, projectRoles, log }: ApplyProjectParams): Promise<void> {
    const existing = await projectMemberRepo().find({
        where: { platformId, userId, managedBy },
    })
    const stale = new Map(existing.map(row => [row.projectId, row]))

    for (const [projectId, role] of projectRoles) {
        const project = await projectService(log).getOne(projectId)
        if (isNil(project) || project.platformId !== platformId || project.type !== ProjectType.TEAM) {
            log.warn({ platformId, projectId, managedBy }, 'Skipping external group grant for missing/non-TEAM project')
            continue
        }
        const current = stale.get(projectId) ?? await projectMemberRepo().findOneBy({ userId, projectId })
        if (!isNil(current) && current.managedBy !== managedBy) continue
        stale.delete(projectId)
        // An administrator can adjust a provider-managed member's role. It
        // remains provider-owned for revocation, but subsequent sync won't undo
        // that explicit role choice.
        if (current?.roleManuallySet) continue
        const projectRoleId = await projectService(log).getOrCreateDefaultProjectRoleId({ platformId, role })
        if (current?.projectRoleId === projectRoleId) continue

        const now = new Date().toISOString()
        await projectMemberRepo()
            .createQueryBuilder()
            .insert()
            .into(ProjectMemberEntity)
            .values({
                id: current?.id ?? apId(),
                userId, projectId, platformId, projectRoleId,
                managedBy, roleManuallySet: false, created: now, updated: now,
            })
            // Preserve both manual grants and a concurrent admin role edit.
            .onConflict('("userId", "projectId") DO UPDATE SET "projectRoleId" = EXCLUDED."projectRoleId", "updated" = EXCLUDED."updated" WHERE "project_member"."managedBy" = \'' + managedBy + '\' AND "project_member"."roleManuallySet" = false')
            .execute()
    }

    const revoked = [...stale.keys()]
    if (revoked.length > 0) {
        await projectMemberRepo().delete({ platformId, userId, managedBy, projectId: In(revoked) })
        websocketService.evictUserFromProjects({ userId, projectIds: revoked })
    }
}

type ApplyParams = {
    platformId: PlatformId
    userId: UserId
    managedBy: ManagedBy
    platformRole: PlatformRole | null
    projectRoles: Map<string, DefaultProjectRole>
}

type ApplyPlatformParams = Omit<ApplyParams, 'projectRoles'> & { log: FastifyBaseLogger }
type ApplyProjectParams = Omit<ApplyParams, 'platformRole'> & { log: FastifyBaseLogger }
