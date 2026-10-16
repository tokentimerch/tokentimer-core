"use strict";
const errors=require("../certops-distribution-inventory").validate();
if(errors.length){console.error(errors.join("\n"));process.exitCode=1;}else console.log("certops-distribution-inventory: mandatory cohorts and fixtures retained");
