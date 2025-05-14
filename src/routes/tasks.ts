import { OpenAPIHono } from '@hono/zod-openapi'
import { z } from 'zod'
import { authMiddleware } from '../middleware/auth'

const app = new OpenAPIHono()

app.openapi(
  {
    method: 'get',
    path: '/api/tasks',
    operationId: 'getTasks',
    summary: 'Get list of tasks',
    tags: ['Tasks'],
    responses: {
      200: {
        description: 'Success',
        content: {
          'application/json': {
            schema: z.array(z.object({ id: z.string(), title: z.string() }))
          }
        }
      }
    }
  },
  authMiddleware,
  (c) => {
    const user = c.get('user')
    return c.json([
      { id: '1', title: 'Task for ' + user?.sub },
      { id: '2', title: 'Another secure task' }
    ])
  }
)


export default app
