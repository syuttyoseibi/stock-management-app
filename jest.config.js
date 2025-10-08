module.exports = {
  testEnvironment: 'node',
  forceExit: true, // This helps ensure Jest exits after tests are done, especially with open handles like a db connection.
  testTimeout: 10000 // Increase timeout for tests that might take longer
};