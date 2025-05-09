import { Hono } from 'hono'
import { jwtVerify } from 'jose'

const app = new Hono()

// Auth middleware
app.use('/api/protected', async (c, next) => {
  const req = c.req
  const authHeader = req.header('Authorization')
  console.log(`[${req.method}] ${req.path}`)

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    console.warn('Missing or malformed Authorization header')
    return c.text('Missing or invalid Authorization header', 401)
  }

  const token = authHeader.slice(7)
  console.log('Auth Token Prefix:', token.slice(0, 10) + '...')

  try {
    // Fetch JWKS
    const JWKS = await fetch(`https://${c.env.AUTH0_DOMAIN}/.well-known/jwks.json`).then(res => res.json())
    const [key] = JWKS.keys // Still using first key for now
    console.log('Using JWKS key ID:', key.kid)

    const keyData = await crypto.subtle.importKey(
      'jwk',
      key,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['verify']
    )

    const { payload, protectedHeader } = await jwtVerify(token, keyData, {
      issuer: `https://${c.env.AUTH0_DOMAIN}/`,
      audience: c.env.AUTH0_AUDIENCE
    })

    console.log('JWT Header:', protectedHeader)
    console.log('JWT Payload:', payload)

    // Distinguish token type
    const flowType = payload.sub?.includes('@clients') ? 'Machine-to-Machine (client credentials)' : 'User Token'
    console.log('Token Type:', flowType)

    // Optional: log roles or permissions
    if (payload.permissions?.length) {
      console.log('Permissions:', payload.permissions)
    }
    if ((payload as any)['https://your-app.com/roles']) {
      console.log('Roles:', (payload as any)['https://your-app.com/roles'])
    }

    c.set('user', payload)
    await next()
  } catch (err) {
    console.error('JWT verification failed:', err)
    return c.text('Unauthorized', 401)
  }
})

// Protected route
app.get('/api/protected', (c) => {
  const user = c.get('user')
  return c.json({ message: 'Access granted', user })
})

export default app
