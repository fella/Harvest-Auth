import { OpenAPIHono } from '@hono/zod-openapi'
import tasksRoute from './routes/tasks'

const app = new OpenAPIHono()

app.route('/', tasksRoute)

app.doc('/openapi.json', {
  openapi: '3.1.0',
  info: {
    title: 'Auth0 Secured API',
    version: '1.0.0'
  }
})
// Protected route
app.get('/', (c) => c.text('Hello World'))
// Middleware for role checking
app.use('/api/protected', async (c, next) => {
  const authHeader = c.req.header('Authorization')
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return c.text('Missing or invalid Authorization header', 401)
  }

  const token = authHeader.slice(7)
  try {
    const JWKS = await fetch(`https://${c.env.AUTH0_DOMAIN}/.well-known/jwks.json`).then(res => res.json())
    const [key] = JWKS.keys
    const keyData = await crypto.subtle.importKey(
      'jwk',
      key,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['verify']
    )
    const { payload } = await jwtVerify(token, keyData, {
      issuer: `https://${c.env.AUTH0_DOMAIN}/`,
      audience: c.env.AUTH0_AUDIENCE
    })

    const roles = payload['https://api.harvest.org/roles'] || []
    if (!roles.includes('admin')) {
      return c.text('Forbidden: Insufficient role', 403)
    }

    c.set('user', payload)
    await next()
  } catch (err) {
    console.error('JWT verification failed', err)
    return c.text('Unauthorized', 401)
  }
})
app.get('/api/protected', (c) => {
  const user = c.get('user')
  return c.json({ message: 'Access granted', user })
})



export default app
