"use strict";
// Host broker primitive. acquire() owns authentication and returns only the
// role's own token. The role sees a read-only directory bind, never assertions.
const assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto");
function createTokenSink({directory,acquire,prepareOwner,now=Date.now}) {
  assert.ok(path.isAbsolute(directory || ""),"absolute sink directory required");
  assert.equal(typeof acquire,"function"); assert.equal(typeof prepareOwner,"function");
  const original=fs.lstatSync(directory);
  assert.ok(original.isDirectory() && !original.isSymbolicLink(),"real sink directory required");
  const resolved=fs.realpathSync(directory), identity=fs.statSync(resolved);
  let active=false;
  async function refresh() {
    assert.equal(active,false,"concurrent token refresh refused"); active=true;
    try { return await writeRefresh(); } finally { active=false; }
  }
  async function writeRefresh() {
    const value=await acquire();
    assert.ok(value && typeof value.accessToken === "string" && value.accessToken.length>0 && Buffer.byteLength(value.accessToken)<12000,"invalid token");
    assert.ok(Number.isFinite(value.expiresOn) && value.expiresOn>now(),"unexpired token required");
    const current=fs.lstatSync(directory), real=fs.realpathSync(directory);
    assert.ok(current.isDirectory() && !current.isSymbolicLink() && real===resolved && current.dev===identity.dev && current.ino===identity.ino,"sink directory changed");
    const tmp=path.join(resolved,`.token-${crypto.randomBytes(16).toString("hex")}`),target=path.join(resolved,"token.json");
    let fd;
    try {
      fd=fs.openSync(tmp,"wx",0o600); prepareOwner(fd);
      fs.writeFileSync(fd,JSON.stringify({accessToken:value.accessToken,expiresOn:value.expiresOn})+"\n");
      fs.fsyncSync(fd); fs.closeSync(fd); fd=undefined;
      fs.renameSync(tmp,target);
    } finally { if(fd!==undefined)fs.closeSync(fd); try{fs.unlinkSync(tmp);}catch(e){if(e.code!=="ENOENT")throw e;} }
    return {expiresOn:value.expiresOn};
  }
  return {refresh};
}
module.exports={createTokenSink};
