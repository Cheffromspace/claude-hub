module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  setupFiles: ['<rootDir>/test/setup.js'],
  testMatch: [
    '**/test/unit/**/*.test.{js,ts}',
    '**/test/integration/**/*.test.{js,ts}',
    '**/test/e2e/scenarios/**/*.test.{js,ts}'
  ],
  transform: {
    '^.+\\.ts$': 'ts-jest',
    '^.+\\.js$': 'babel-jest'
  },
  moduleFileExtensions: ['ts', 'js', 'json'],
  transformIgnorePatterns: [
    'node_modules/(?!(universal-user-agent|@octokit|before-after-hook)/)'
  ],
  collectCoverage: true,
  coverageReporters: ['text', 'lcov'],
  coverageDirectory: 'coverage',
  coveragePathIgnorePatterns: [
    '/node_modules/',
    '/dist/',
    '/coverage/'
  ],
  collectCoverageFrom: [
    'src/**/*.{js,ts}',
    '!src/**/*.d.ts',
    '!src/types/**/*.ts',
    '!**/node_modules/**',
    '!**/dist/**'
  ],
  testTimeout: 30000, // Some tests might take longer due to container initialization
  verbose: true,
  reporters: [
    'default',
    ['jest-junit', { outputDirectory: 'test-results/jest', outputName: 'results.xml' }]
  ]
};