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
app.get('/api/protected', (c) => {
  const user = c.get('user')
  return c.json({ message: 'Access granted', user })
})

export default app
