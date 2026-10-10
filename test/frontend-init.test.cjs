const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const source=fs.readFileSync(path.join(__dirname,'../app.js'),'utf8');
const begin=source.indexOf('async function initPeer(){');
const end=source.indexOf('\nfunction handleIncoming',begin);
const fn=source.slice(begin,end);
function fixture(){const calls={sessions:0,peers:0,failures:0};const state={name:'fixture',deviceId:'registered-fixture',peerId:'dm-'+ '1'.repeat(30),identity:{},peer:null,peerReady:false};const context={state,privateMode:true,runtimeConfig:{},clearPeerRetryTimer(){},ensurePeerId(){},render(){},loadIdentity:async()=>({}),requestPrivateSession:async()=>{calls.sessions++;await Promise.resolve();return {signalToken:'test-only-token',iceServers:[]};},handleAuthFailure(){calls.failures++;},Peer:class{constructor(){calls.peers++;}on(){return this;}},console,setTimeout,clearTimeout};vm.createContext(context);vm.runInContext(fn+';globalThis.start=initPeer;',context);return {calls,state,context};}
test('concurrent startup/visibility/online uses only one signed session and one Peer',async()=>{const f=fixture();await Promise.all([f.context.start(),f.context.start(),f.context.start()]);assert.equal(f.calls.sessions,1);assert.equal(f.calls.peers,1);assert.equal(f.state.peerInitBusy,false);});
test('failed authentication releases initialization lock for retry',async()=>{const f=fixture();f.context.requestPrivateSession=async()=>{throw new Error('fixture failure');};await f.context.start();assert.equal(f.calls.failures,1);assert.equal(f.state.peerInitBusy,false);f.context.requestPrivateSession=async()=>({signalToken:'test-only-token',iceServers:[]});await f.context.start();assert.equal(f.calls.peers,1);});
test('identity load failure cannot permanently hold initialization lock',async()=>{const f=fixture();f.state.identity=null;f.context.loadIdentity=async()=>{throw new Error('fixture failure');};await assert.rejects(f.context.start());assert.equal(f.state.peerInitBusy,false);});
