/**
 * Create the agent-local revocation-validation deadline for a newly deferred enrollment.
 * Protected host configuration may shorten the default24-hour window to at least five
 * minutes. Continuation code retains an existing journal deadline across restart. */
"use strict";
const DEFAULT_VALIDATION_TIMEOUT_SECONDS=86400;
const MIN_VALIDATION_TIMEOUT_SECONDS=300;
function validateValidationTimeoutSeconds(value){
  if(!Number.isInteger(value)||value<MIN_VALIDATION_TIMEOUT_SECONDS||value>DEFAULT_VALIDATION_TIMEOUT_SECONDS)throw new TypeError("adcs.validationTimeoutSeconds must be an integer from 300 to 86400");
  return value;
}
function newValidationDeadline(executionContext){
  const configured=executionContext.adcsValidationTimeoutSeconds;
  const seconds=configured===undefined?DEFAULT_VALIDATION_TIMEOUT_SECONDS:validateValidationTimeoutSeconds(configured);
  return new Date(Date.now()+seconds*1000).toISOString();
}
module.exports={DEFAULT_VALIDATION_TIMEOUT_SECONDS,MIN_VALIDATION_TIMEOUT_SECONDS,validateValidationTimeoutSeconds,newValidationDeadline};
