"use strict";

// Shared deterministic calendar evaluation. Convert real UTC instants into
// IANA wall time; never guess a UTC offset or manufacture a missing DST hour.
const METHODS=Object.freeze(["none","reload","rebind","no-restart-refresh","controlled-restart","manual"]);
const formatters=new Map();
function invalid(){const error=new Error("CERTOPS_ACTIVATION_POLICY_INVALID");error.code="CERTOPS_ACTIVATION_POLICY_INVALID";error.statusCode=422;throw error;}
function exact(value,keys){if(!value || typeof value!=="object" || Array.isArray(value) ||
  Object.keys(value).length!==keys.length || keys.some(key=>!Object.hasOwn(value,key)))invalid();}
function validateActivationPolicy(policy){
  exact(policy,["method","disruptive","requiresApproval","timezone","windows","blackouts","validUntil","emergency"]);
  if(!METHODS.includes(policy.method) || typeof policy.disruptive!=="boolean" || typeof policy.requiresApproval!=="boolean")invalid();
  if(policy.method==="controlled-restart" && (!policy.disruptive || !policy.requiresApproval))invalid();
  if(typeof policy.timezone!=="string" || policy.timezone.length>100 || !/^[A-Za-z_+-]+(?:\/[A-Za-z0-9_+-]+)*$/.test(policy.timezone))invalid();
  try{new Intl.DateTimeFormat("en-US",{timeZone:policy.timezone}).format(0);}catch{invalid();}
  if(!Array.isArray(policy.windows) || policy.windows.length>32 || !Array.isArray(policy.blackouts) || policy.blackouts.length>64)invalid();
  const time=/^(?:[01]\d|2[0-3]):[0-5]\d$/;
  for(const window of policy.windows){exact(window,["days","start","end"]);
    if(!Array.isArray(window.days) || !window.days.length || window.days.length>7 || window.days.some(day=>!Number.isInteger(day)||day<0||day>6) ||
      new Set(window.days).size!==window.days.length || !time.test(window.start) || !time.test(window.end) || window.start===window.end)invalid();}
  const instant=value=>typeof value==="string" && value.length<=40 && /(?:Z|[+-]\d\d:\d\d)$/.test(value) && Number.isFinite(Date.parse(value));
  for(const blackout of policy.blackouts){exact(blackout,["start","end"]);if(!instant(blackout.start)||!instant(blackout.end)||Date.parse(blackout.end)<=Date.parse(blackout.start))invalid();}
  if(policy.validUntil!==null && !instant(policy.validUntil))invalid();
  if(policy.emergency!==null){exact(policy.emergency,["start","end","reference"]);
    if(!instant(policy.emergency.start)||!instant(policy.emergency.end)||Date.parse(policy.emergency.end)<=Date.parse(policy.emergency.start)||
      Date.parse(policy.emergency.end)-Date.parse(policy.emergency.start)>4*3600000 || !/^[A-Za-z0-9_-]{1,64}$/.test(policy.emergency.reference))invalid();}
  return policy;
}
const minute=value=>Number(value.slice(0,2))*60+Number(value.slice(3));
function wallTime(timezone,now){
  if(!formatters.has(timezone))formatters.set(timezone,new Intl.DateTimeFormat("en-US",{timeZone:timezone,weekday:"short",hour:"2-digit",minute:"2-digit",hourCycle:"h23"}));
  const parts=Object.fromEntries(formatters.get(timezone).formatToParts(now).map(part=>[part.type,part.value]));
  return {day:["Sun","Mon","Tue","Wed","Thu","Fri","Sat"].indexOf(parts.weekday),minute:Number(parts.hour)*60+Number(parts.minute)};
}
function activationDecision(policy,now=Date.now()){
  if(!policy)return {allowed:true,reason:"legacy_local_policy"};
  validateActivationPolicy(policy);
  if(!Number.isFinite(now))invalid();
  return evaluateValidated(policy,now);
}
function evaluateValidated(policy,now){
  if(policy.validUntil && now>=Date.parse(policy.validUntil))return {allowed:false,reason:"activation_authorization_expired"};
  if(policy.method==="manual")return {allowed:false,reason:"manual_activation_required"};
  if(policy.blackouts.some(period=>now>=Date.parse(period.start)&&now<Date.parse(period.end)))return {allowed:false,reason:"maintenance_blackout"};
  if(policy.emergency && now>=Date.parse(policy.emergency.start)&&now<Date.parse(policy.emergency.end))return {allowed:true,reason:"emergency_authorization"};
  if(!policy.windows.length)return {allowed:!policy.disruptive,reason:policy.disruptive?"maintenance_window_required":"non_disruptive"};
  const wall=wallTime(policy.timezone,now);
  const allowed=policy.windows.some(window=>{
    const start=minute(window.start),end=minute(window.end);
    return start<end ? window.days.includes(wall.day)&&wall.minute>=start&&wall.minute<end
      : window.days.includes(wall.day)&&wall.minute>=start || window.days.includes((wall.day+6)%7)&&wall.minute<end;
  });
  return {allowed,reason:allowed?"maintenance_window_open":"outside_maintenance_window"};
}
function nextActivation(policy,expiry,now=Date.now()){
  if(!policy)return {at:new Date(now).toISOString(),reason:"legacy_local_policy"};
  validateActivationPolicy(policy);
  const end=Date.parse(expiry),horizon=Math.min(end,now+35*86400000);
  if(!Number.isFinite(end) || end<=now)return {at:null,reason:"no_window_before_expiry"};
  const initial=evaluateValidated(policy,now);if(initial.allowed)return {at:new Date(now).toISOString(),reason:initial.reason};
  if(["activation_authorization_expired","manual_activation_required","maintenance_window_required"].includes(initial.reason))return {at:null,reason:initial.reason};
  for(let instant=Math.ceil(now/60000)*60000;instant<horizon;instant+=60000){
    if(evaluateValidated(policy,instant).allowed)return {at:new Date(instant).toISOString(),reason:"scheduled"};
  }
  return {at:null,reason:horizon===end?"no_window_before_expiry":"maintenance_search_horizon_exceeded"};
}
module.exports={METHODS,validateActivationPolicy,activationDecision,nextActivation};
