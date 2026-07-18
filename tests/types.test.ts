import type { Request, Response } from 'express'
import { createClient } from 'redis'
import { auth, configure, generateToken, initialize, type AuthContext, type TokenData } from '..'

const tokenData: TokenData = {
  userId: 'user-1',
  role: 'admin',
  permissions: ['read'],
}

void generateToken(tokenData)
configure({ security: { allowedTokenFields: ['userId', 'role', 'permissions'] } })
void initialize({ redisClient: createClient() })

function handler(req: Request, res: Response) {
  const context: AuthContext | undefined = req.auth
  return res.json({ user: context?.decoded, session: context?.session })
}

void auth
void handler
