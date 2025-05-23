import { Hono } from 'hono'
import { jwtVerify, decodeProtectedHeader } from 'jose'

const app = new Hono()

// Auth middleware here!

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
    // Step 1: Decode JWT header to extract `kid`
    const { kid } = decodeProtectedHeader(token)
    console.log('JWT Header kid:', kid)

    // Step 2: Fetch JWKS from Auth0
    const jwksUrl = `https://${c.env.AUTH0_DOMAIN}/.well-known/jwks.json`
    const JWKS = await fetch(jwksUrl).then(res => res.json())

    const key = JWKS.keys.find(k => k.kid === kid)
    if (!key) {
      console.error(`No matching JWKS key found for kid: ${kid}`)
      return c.text('Unauthorized - JWKS key not found', 401)
    }

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

    console.log('JWT Payload:', payload)

    const flowType = payload.sub?.includes('@clients') ? 'Machine-to-Machine (client credentials)' : 'User Token'
    console.log('Token Type:', flowType)

    if (payload.permissions?.length) {
      console.log('Permissions:', payload.permissions)
    }

    if ((payload as any)['https://harvorg.webdept.org/roles']) {
      console.log('Roles:', (payload as any)['https://harvorg.webdept.org/roles'])
    }

    c.set('user', payload)
    await next()
  } catch (err) {
    console.error('JWT verification failed:', err)
    return c.text('Unauthorized', 401)
  }
})

// Check for roles
app.use('/api/protected', async (c, next) => {
  const token = c.req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return c.text('Missing Authorization header', 401);

  try {
    const { payload } = await verifyToken(token, c.env); // Your jwtVerify logic

    const roles = (payload as any)['https://harvorg.webdept.org/roles']?.split(',') || [];

    // Only allow users with the 'Editor' role
    if (!roles.includes('Editor')) {
      return c.text('Forbidden: Insufficient role', 403);
    }

    c.set('user', payload);
    await next();
  } catch (err) {
    console.error('JWT verification failed:', err);
    return c.text('Unauthorized', 401);
  }
});

// Check for roles
app.get('/api/admin-only', (c) => {
  const user = c.get('user');
  const roles = (user as any)['https://harvorg.webdept.org/roles']?.split(',') || [];

  if (!roles.includes('Admin')) {
    return c.text('Forbidden: Admins only', 403);
  }

  return c.json({ message: 'Welcome, Admin!', user });
});



export default app
