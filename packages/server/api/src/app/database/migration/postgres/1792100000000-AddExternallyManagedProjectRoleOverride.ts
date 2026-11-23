import { QueryRunner } from 'typeorm'
import { Migration } from '../../migration'

// Keeps group-derived membership provenance independent from a human's role
// adjustment. Losing the authoritative group still revokes the membership.
export class AddExternallyManagedProjectRoleOverride1792100000000 implements Migration {
    name = 'AddExternallyManagedProjectRoleOverride1792100000000'
    breaking = false
    release = '2.0.0'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query('ALTER TABLE "project_member" ADD "roleManuallySet" boolean NOT NULL DEFAULT false')
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query('ALTER TABLE "project_member" DROP COLUMN "roleManuallySet"')
    }
}
