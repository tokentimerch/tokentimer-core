/**
 * Match a complete local AD CS enrollment rule across CA, template, names and key algorithm.
 * The production enrollment executor must not combine partial permissions from different
 * rules. CA/template-only entries remain valid for read-only preflight, not enrollment. */
"use strict";
const ZONE=/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/i;
function normalizeRuleConstraints(rule,label="AD CS enrollment rule") {
  const result={};
  for(const field of ["dnsScopes","keyAlgorithms"]){
    if(rule[field]===undefined)continue;
    const list=rule[field],limit=field==="dnsScopes"?32:2;
    if(!Array.isArray(list)||list.length<1||list.length>limit)throw new Error(`${label}.${field} must be a nonempty array with at most ${limit} entries`);
    const normalized=list.map(value=>{
      if(typeof value!=="string" || (field==="dnsScopes" ? value.length>253||!ZONE.test(value) : !["rsa","ecdsa"].includes(value)))throw new Error(`${label}.${field} contains an invalid value`);
      return field==="dnsScopes"?value.toLowerCase():value;
    });
    if(new Set(normalized).size!==normalized.length)throw new Error(`${label}.${field} must contain unique entries`);
    result[field]=normalized;
  }
  return result;
}
function matchWholeEnrollmentRule(rules,caConfig,template,context){
  if(!Array.isArray(rules))return null;
  for(const rule of rules){
    if(!rule||rule.caConfig!==caConfig||rule.template!==template)continue;
    let constraints;try{constraints=normalizeRuleConstraints(rule);}catch{continue;}
    // Read-only preflight has no requested certificate/key. It checks only the
    // exact pair, while still refusing malformed configured constraints.
    if(context){
      if(!constraints.dnsScopes||!constraints.keyAlgorithms||!Array.isArray(context.authorizedDnsNames)||!context.authorizedDnsNames.length||!Array.isArray(context.extraDnsNames||[]))continue;
      const names=[...(context.authorizedDnsNames||[]),...(context.extraDnsNames||[])];
      if(constraints.dnsScopes && (!names.length||names.some(name=>typeof name!=="string"||name.length>253||!ZONE.test(name.startsWith("*.")?name.slice(2):name)||!constraints.dnsScopes.some(zone=>name.toLowerCase()===zone||name.toLowerCase().endsWith(`.${zone}`)))))continue;
      if(constraints.keyAlgorithms&&!constraints.keyAlgorithms.includes(context.keyAlgorithm))continue;
    }
    return rule;
  }
  return null;
}
module.exports={normalizeRuleConstraints,matchWholeEnrollmentRule};
