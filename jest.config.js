module.exports = {
  testEnvironment: 'node',
  coverageDirectory: 'coverage',
  collectCoverageFrom: [
    '**/*.js',
    '!jest.config.js',
    '!coverage/**',
    '!node_modules/**',
    '!tests/**',
  ],
  testMatch: ['**/tests/**/*.test.js'],
  testTimeout: 10000,
  setupFilesAfterEnv: ['./tests/setup.js'],
}
