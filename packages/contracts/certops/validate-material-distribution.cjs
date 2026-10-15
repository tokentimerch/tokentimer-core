"use strict";
const Ajv=require("ajv");
const addFormats=require("ajv-formats");
const schema=require("./material-distribution.schema.json");
const ajv=new Ajv({allErrors:false,strict:false});
addFormats(ajv);ajv.addSchema(schema);
const validators=Object.fromEntries(["publication","materialDeployment","publicationReceipt","deploymentReceipt","consumerBinding"].map(name=>[name,ajv.compile({$ref:`${schema.$id}#/definitions/${name}`})]));
module.exports={validate:(name,value)=>validators[name]?.(value)===true};
