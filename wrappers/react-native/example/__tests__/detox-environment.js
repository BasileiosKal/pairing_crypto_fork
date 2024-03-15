const { DetoxCircusEnvironment } = require('detox/runners/jest');
const { FixturesEnvName, readFixtureFiles } = require('../__fixtures__/fixture-loader');

class CustomDetoxEnvironment extends DetoxCircusEnvironment {
  constructor(config, context) {
    super(config, context);
  }

  async setup() {
    await super.setup();

    // Load and inject the generated test fixtures to be accessed from the tests suites.
    process.env[FixturesEnvName] = readFixtureFiles();
  }
}

module.exports = CustomDetoxEnvironment;
