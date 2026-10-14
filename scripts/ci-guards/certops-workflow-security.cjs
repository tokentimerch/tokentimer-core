/**
 * Apply the shared qualification workflow security policy to the checked-in YAML.
 * Only trusted refs, pinned actions, bounded privileges and owned cleanup are accepted. */
"use strict";
const {check}=require("../certops-workflow-security");const errors=check();if(errors.length){console.error(errors.join("\n"));process.exitCode=1;}else console.log("certops-workflow-security: trusted qualification workflow boundaries valid");
