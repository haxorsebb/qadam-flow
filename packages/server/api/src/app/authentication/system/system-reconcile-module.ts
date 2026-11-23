import { FastifyPluginAsyncZod } from 'fastify-type-provider-zod'
import { SystemJobName } from '../../helper/system-jobs/common'
import { systemJobHandlers } from '../../helper/system-jobs/job-handlers'
import { systemJobsSchedule } from '../../helper/system-jobs/system-job'
import { systemReconcileService } from './system-reconcile-service'

// Scheduler is registered even if SYSTEM authentication is off: the handler
// rechecks the flag on each run. One minute bounds normal group-revocation
// propagation in addition to the host SSSD/NSS cache expiry.
export const systemReconcileModule: FastifyPluginAsyncZod = async (app) => {
    systemJobHandlers.registerJobHandler(SystemJobName.SYSTEM_RECONCILE, async () => {
        await systemReconcileService(app.log).reconcileAllPlatforms()
    })
    await systemJobsSchedule(app.log).upsertJob({
        job: {
            name: SystemJobName.SYSTEM_RECONCILE,
            data: {},
            jobId: SystemJobName.SYSTEM_RECONCILE,
        },
        schedule: { type: 'repeated', cron: '* * * * *' },
    })
}
