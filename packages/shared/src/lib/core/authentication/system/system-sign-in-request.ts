import { z } from 'zod'
import { formErrors } from '../../../form-errors'

// The appliance's canonical Linux username is not necessarily an email address.
export const SystemSignInRequest = z.object({
    username: z.string().min(1, formErrors.required).max(256),
    password: z.string().min(1, formErrors.required).max(1024),
})
export type SystemSignInRequest = z.infer<typeof SystemSignInRequest>
