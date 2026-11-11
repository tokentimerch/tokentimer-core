"use strict";
/* Supporting timer scheduling regression: controlled monotonic readings prove
 * early wakes cannot shorten native fixture holding. No clocks are changed. */
const assert=require("node:assert/strict");
const test=require("node:test");
const {waitMonotonicAtLeast}=require("../tests/e2e/helpers/certops-native-dispatch-timing");
test("an early timer wake waits again until the actual monotonic deadline",async()=>{
 let clock=100;const waits=[];
 const elapsed=await waitMonotonicAtLeast(5000,{now:()=>clock,sleep:async ms=>{waits.push(ms);clock+=waits.length===1?4999.25:ms;}});
 assert.deepEqual(waits,[5000,1]);assert.equal(elapsed,5000.25);
});
test("cancellation before or during a hold refuses early success",async()=>{
 const before=new AbortController();before.abort(new Error("owned fixture stopped"));let calls=0;
 await assert.rejects(waitMonotonicAtLeast(5000,{signal:before.signal,now:()=>0,sleep:async()=>{calls++;}}),/owned fixture stopped/);
 assert.equal(calls,0);
 const during=new AbortController();let clock=0;
 await assert.rejects(waitMonotonicAtLeast(5000,{signal:during.signal,now:()=>clock,sleep:async()=>{clock=1;during.abort(new Error("owned fixture stopped"));}}),/owned fixture stopped/);
});
test("oversleep and backwards readings fail instead of fabricating valid elapsed evidence",async()=>{
 let clock=0;await assert.rejects(waitMonotonicAtLeast(5000,{now:()=>clock,sleep:async()=>{clock=60001;}}),/reviewed bound/);
 clock=100;await assert.rejects(waitMonotonicAtLeast(5000,{now:()=>clock,sleep:async()=>{clock=99;}}),/moved backwards/);
 await assert.rejects(waitMonotonicAtLeast(5000,{maxWaitMs:60001}));
});
