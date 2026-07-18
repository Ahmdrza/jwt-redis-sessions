const { spawn } = require('node:child_process')
const { RedisMemoryServer } = require('redis-memory-server')

async function run() {
  const redisServer = await RedisMemoryServer.create({
    binary: { version: '7.4.9' },
  })

  try {
    const host = await redisServer.getHost()
    const port = await redisServer.getPort()
    await new Promise((resolve, reject) => {
      const child = spawn(process.execPath, ['tests/redis.integration.js'], {
        cwd: process.cwd(),
        env: { ...process.env, REDIS_URL: `redis://${host}:${port}` },
        stdio: 'inherit',
      })
      child.once('error', reject)
      child.once('exit', (code, signal) => {
        if (code === 0) {
          resolve()
        } else {
          reject(new Error(`Redis integration exited with ${signal || `code ${code}`}`))
        }
      })
    })
  } finally {
    await redisServer.stop()
  }
}

run().catch((error) => {
  process.stderr.write(`${error.stack || error.message}\n`)
  process.exitCode = 1
})
