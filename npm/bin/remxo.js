#!/usr/bin/env node
'use strict';

const { launch, reportFailure } = require('../lib/launch');

try {
  launch(process.argv.slice(2));
} catch (error) {
  reportFailure(error);
}
