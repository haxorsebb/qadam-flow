import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import {
    DefaultProjectRole, PlatformId, PlatformRole,
    ProjectMemberManagedBy, ProjectType, UserId,
} from '@aiqadam/shared'
import { FastifyBaseLogger } from 'fastify'
import { IsNull } from 'typeorm'
import { distributedLock } from '../../database/redis-connections'
import { platformService } from '../../platform/platform.service'
import { projectRepo } from '../../project/project-repo'
import { projectService } from '../../project/project-service'
import { managedGroupGrantService } from '../managed-group-grant-service'

const execFileAsync = promisify(execFile)

// GIDs are stable through group renames; names become Qadam's initial TEAM
// display names, but administrators own display names from that point onward.
export type MarkedGroup = { gid: number, name: string }
const externalIdFor = (group: MarkedGroup): string => `system-group:gid:${group.gid}`

export const systemGroupService = (log: FastifyBaseLogger) => ({
    async listMarkedGroups(): Promise<MarkedGroup[] | null> {
        const marker = process.env.AP_SYSTEM_AUTH_GROUP_MARKER ?? 'qadam-group-marker'
        try {
            const [ids, names] = await Promise.all([
                execFileAsync('id', ['-G', marker]),
                execFileAsync('id', ['-nG', marker]),
            ])
            const gids = ids.stdout.trim().split(/\s+/)
            const groupNames = names.stdout.trim().split(/\s+/)
            if (gids.length !== groupNames.length) return null
            const result: MarkedGroup[] = []
            for (let i = 0; i < gids.length; i++) {
                const gid = Number(gids[i])
                if (!Number.isSafeInteger(gid) || gid < 0) return null
                if (groupNames[i] !== marker) result.push({ gid, name: groupNames[i] })
            }
            return result
        }
        catch (error) {
            log.error({ err: error, marker }, 'Cannot resolve SYSTEM marker group memberships')
            return null
        }
    },

    async listUserGroups(username: string): Promise<string[] | null> {
        try {
            const { stdout } = await execFileAsync('id', ['-nG', username])
            return stdout.trim().split(/\s+/).filter(Boolean)
        }
        catch {
            return null
        }
    },

    // This is the SYSTEM provider's group policy. The actual Qadam role and
    // membership writes are shared with LDAP by managedGroupGrantService.
    async reconcileUser({ platformId, userId, groups, marked }: ReconcileUserParams): Promise<void> {
        const membership = new Set(groups)
        const projects = await this.ensureMarkedTeamProjects({ platformId, marked })
        const projectRoles = new Map<string, DefaultProjectRole>()
        for (const group of marked) {
            if (!membership.has(group.name)) continue
            const project = projects.get(group.gid)
            if (project) projectRoles.set(project, DefaultProjectRole.VIEWER)
        }
        const adminGroup = process.env.AP_SYSTEM_AUTH_ADMIN_GROUP ?? 'qadam-admins'
        const platformRole = marked.some(group => group.name === adminGroup && membership.has(group.name))
            ? PlatformRole.ADMIN : null
        await managedGroupGrantService(log).apply({
            platformId, userId, managedBy: ProjectMemberManagedBy.SYSTEM, platformRole, projectRoles,
        })
    },

    async ensureMarkedTeamProjects({ platformId, marked }: EnsureParams): Promise<Map<number, string>> {
        return distributedLock(log).runExclusive({
            key: `system-marked-projects:${platformId}`,
            timeoutInSeconds: 30,
            fn: async () => {
                const owner = (await platformService(log).getOneOrThrow(platformId)).ownerId
                const projects = new Map<number, string>()
                for (const group of marked) {
                    const externalId = externalIdFor(group)
                    let project = await projectRepo().findOneBy({ platformId, externalId, type: ProjectType.TEAM })
                    if (!project) {
                        // Fresh appliances start without TEAM projects, but adopting a
                        // pre-created same-name TEAM is explicitly supported.
                        const named = await projectRepo().findOneBy({
                            platformId, displayName: group.name, type: ProjectType.TEAM,
                        })
                        if (named) {
                            if (named.externalId && named.externalId !== externalId) {
                                log.error({ platformId, group: group.name, projectId: named.id },
                                    'TEAM name already belongs to another external group; refusing reassociation')
                                continue
                            }
                            if (!named.externalId) {
                                await projectRepo().update({ id: named.id, externalId: IsNull() }, { externalId })
                            }
                            project = await projectRepo().findOneBy({ platformId, externalId, type: ProjectType.TEAM })
                        }
                    }
                    if (!project) {
                        project = await projectService(log).create({
                            platformId,
                            ownerId: owner,
                            displayName: group.name,
                            type: ProjectType.TEAM,
                            externalId,
                            callPostCreateHooks: false,
                        })
                    }
                    projects.set(group.gid, project.id)
                }
                return projects
            },
        })
    },
})

type EnsureParams = { platformId: PlatformId, marked: MarkedGroup[] }
type ReconcileUserParams = EnsureParams & { userId: UserId, groups: string[] }
