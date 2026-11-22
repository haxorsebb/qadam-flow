import { FastifyPluginAsyncZod } from 'fastify-type-provider-zod'
import { systemAuthnController } from './system-authn-controller'

export const systemAuthnModule: FastifyPluginAsyncZod = async (app) => {
    await app.register(systemAuthnController, { prefix: '/v1/authn/system' })
}
