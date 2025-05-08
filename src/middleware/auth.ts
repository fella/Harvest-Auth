import { MiddlewareHandler } from 'hono'
import { createRemoteJWKSet, jwtVerify } from 'jose'

export const authMiddleware: MiddlewareHandler = async (c, next) => {
  const authHeader = c.req.header('Authorization')
  if (!authHeader?.startsWith('Bearer ')) return c.text('Unauthorized', 401)

  const token = authHeader.split(' ')[1]
  const domain = c.env.AUTH0_DOMAIN
  const audience = c.env.AUTH0_AUDIENCE

  const JWKS = createRemoteJWKSet(new URL(`https://${domain}/.well-known/jwks.json`))

  try {
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: `https://${domain}/`,
      audience,
    })
    c.set('user', payload)
    await next()
  } catch (err) {
    console.error(err)
    return c.text('Invalid token', 401)
  }
}
