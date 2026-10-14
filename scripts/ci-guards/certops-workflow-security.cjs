"use strict";
const {check}=require("../certops-workflow-security");const errors=check();if(errors.length){console.error(errors.join("\n"));process.exitCode=1;}else console.log("certops-workflow-security: trusted qualification workflow boundaries valid");
