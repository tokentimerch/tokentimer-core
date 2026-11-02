"use strict";

const contract = require("../tests/e2e/helpers/certops-adcs-install-interruption");

function main() {
  return contract.dispatch();
}

if (require.main === module) process.exit(main());

module.exports = { main, dispatch: (options) => contract.dispatch(options) };
