const { execFileSync } = require('node:child_process')
const { mkdtempSync } = require('node:fs')
const { tmpdir } = require('node:os')
const { join } = require('node:path')

const npmCache = mkdtempSync(join(tmpdir(), 'jwt-redis-sessions-npm-'))

const output = execFileSync('npm', ['pack', '--dry-run', '--json'], {
  encoding: 'utf8',
  env: { ...process.env, npm_config_ignore_scripts: 'true', npm_config_cache: npmCache },
})
const pack = JSON.parse(output)[0]
const files = new Set(pack.files.map((file) => file.path))

for (const required of ['README.md', 'SECURITY.md', 'MIGRATION.md', 'index.d.ts']) {
  if (!files.has(required)) {
    throw new Error(`Package is missing required file: ${required}`)
  }
}

for (const forbidden of [
  '.env',
  'CHANGELOG.md',
  'docs/security.md',
  'docs/api-reference.md',
  'tests/setup.js',
  'eslint.config.js',
  'jest.config.js',
]) {
  if (files.has(forbidden)) {
    throw new Error(`Package includes forbidden file: ${forbidden}`)
  }
}

process.stdout.write(`Package contents verified (${files.size} files)\n`)
