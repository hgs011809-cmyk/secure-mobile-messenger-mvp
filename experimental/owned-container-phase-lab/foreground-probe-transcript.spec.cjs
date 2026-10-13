'use strict';
// Synthetic format fixtures only. No command execution, children, network, CI or crypto proof.
const assert=require('node:assert/strict'),{createHash}=require('node:crypto');
const {adaptTranscript,CAPS}=require('./foreground-probe-transcript.cjs');
const release=Buffer.from('Origin: Ubuntu\nLabel: Ubuntu\nSuite: noble\nVersion: 24.04\nCodename: noble\nDate: Thu, 25 Apr 2024 15:10:33 UTC\nSHA256:\n '+'a'.repeat(64)+' 42 main/binary-amd64/Packages\n');
const status=Buffer.from('[GNUPG:] NEWSIG\n[GNUPG:] KEY_CONSIDERED '+ 'A'.repeat(40)+' 0\n[GNUPG:] GOODSIG '+ 'B'.repeat(16)+' SYNTHETIC_PRIVATE_UID\n[GNUPG:] VALIDSIG '+ 'A'.repeat(40)+' 2024-04-25 1714057833 0 4 0 1 10 01 '+ 'C'.repeat(40)+'\n');
const signedInput=Buffer.from('-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n'+release.toString('ascii')+'-----BEGIN PGP SIGNATURE-----\n\nwgEE\n-----END PGP SIGNATURE-----\n');
const retained={signedInput,releaseOutput:release,status,stderr:Buffer.from('')};
function hash(b){return createHash('sha256').update(b).digest('hex');}function bind(b){return {bytes:b.length,sha256:hash(b)};}
function receipt(r=retained){return JSON.stringify({kind:'direct_foreground_gpgv_transcript',version:1,gpgv:{id:'gpgv',input:bind(r.signedInput),output:bind(r.releaseOutput),exitCode:0,signal:null,timeout:false,closed:true},status:bind(r.status),stderr:bind(r.stderr)});}
let passed=0,failed=0;function test(n,f){try{f();passed++;console.log('ok '+n);}catch(e){failed++;console.log('not_ok '+n+' '+(e&&e.message||'error'));}}
function rejects(fn){assert.throws(fn,e=>e&&e.code==='invalid_transcript'&&e.message==='TRANSCRIPT_BLOCKED');}
function run(r=receipt(),b=retained){return adaptTranscript(r,b);}
test('direct_gpgv_then_pure_parser_only',()=>{const o=run();assert.deepEqual(o.stageOrder,['direct_foreground_gpgv','pure_parser']);assert.equal(o.gpgvCompletionDeclared,true);assert.equal(o.parserStage,'pure_node_projection');assert.equal(o.signedInputProfile.cleartextBodyBytes,release.length);assert.equal(o.signedInputProfile.cryptographicVerification,false);});
test('trust_and_authority_never_inferred',()=>{const o=run();for(const k of ['cryptographicVerification','trustedSigner','currentSignerAllowlistChecked','freshnessChecked','fullDebianChainChecked','buildAcceptance','sourceResourceClosureProven'])assert.equal(o[k],false);assert.equal(o.statusSequenceConsistent,true);});
test('output_deep_frozen',()=>{const o=run();assert(Object.isFrozen(o)&&Object.isFrozen(o.stageOrder)&&Object.isFrozen(o.releaseCandidate)&&Object.isFrozen(o.statusCounts));});
test('uid_fingerprints_and_raw_diagnostics_redacted',()=>{const s=JSON.stringify(run());for(const secret of ['SYNTHETIC_PRIVATE_UID','A'.repeat(40),'B'.repeat(16),'[GNUPG:]'])assert(!s.includes(secret));});
test('private_copy_unaffected_by_later_mutation',()=>{const original=Buffer.from(signedInput),r={...retained,signedInput:original};const o=run(receipt(r),r),hashAtReturn=o.retainedByteHashes.signedInput;original.fill(0);assert.equal(o.retainedByteHashes.signedInput,hashAtReturn);});
test('nonzero_exit_rejected',()=>{const x=JSON.parse(receipt());x.gpgv.exitCode=1;rejects(()=>run(JSON.stringify(x)));});
test('signal_rejected',()=>{const x=JSON.parse(receipt());x.gpgv.signal='SIGTERM';rejects(()=>run(JSON.stringify(x)));});
test('timeout_rejected',()=>{const x=JSON.parse(receipt());x.gpgv.timeout=true;rejects(()=>run(JSON.stringify(x)));});
test('not_closed_rejected',()=>{const x=JSON.parse(receipt());x.gpgv.closed=false;rejects(()=>run(JSON.stringify(x)));});
test('incomplete_receipt_rejected',()=>{const x=JSON.parse(receipt());delete x.status;rejects(()=>run(JSON.stringify(x)));});
test('extra_stage_unknown_key_rejected',()=>{const x=JSON.parse(receipt());x.gpg= x.gpgv;rejects(()=>run(JSON.stringify(x)));});
test('wrong_order_or_id_rejected',()=>{const x=JSON.parse(receipt());x.gpgv.id='gpg';rejects(()=>run(JSON.stringify(x)));});
test('misbound_input_hash_and_size_rejected',()=>{for(const alter of [x=>x.gpgv.input.sha256='0'.repeat(64),x=>x.gpgv.input.bytes=Number.MAX_SAFE_INTEGER]){const x=JSON.parse(receipt());alter(x);rejects(()=>run(JSON.stringify(x)));}});
test('misbound_output_status_stderr_rejected',()=>{for(const alter of [x=>x.gpgv.output.bytes++,x=>x.status.sha256='0'.repeat(64),x=>x.stderr.bytes=1]){const x=JSON.parse(receipt());alter(x);rejects(()=>run(JSON.stringify(x)));}});
test('duplicate_key_rejected',()=>rejects(()=>run(receipt().replace('"version":1','"version":1,"version":1'))));
test('noncanonical_and_numeric_rounding_rejected',()=>{rejects(()=>run(' '+receipt()));rejects(()=>run(receipt().replace('"version":1','"version":1.0')));});
test('nested_receipt_depth_bounded',()=>rejects(()=>run('['.repeat(13)+'0'+']'.repeat(13))));
test('receipt_and_all_transcript_caps',()=>{rejects(()=>run(' '.repeat(CAPS.receipt+1)));for(const [k,cap] of [['signedInput',CAPS.input],['releaseOutput',CAPS.release],['status',CAPS.status],['stderr',CAPS.stderr]]){const b={...retained,[k]:Buffer.alloc(cap+1)};rejects(()=>run(receipt(b),b));}});
test('malformed_clear_signed_profile_normalized',()=>{const b={...retained,signedInput:Buffer.from('bad')};assert.throws(()=>run(receipt(b),b),e=>e.message==='TRANSCRIPT_BLOCKED'&&e.code==='invalid_transcript');});
test('release_profile_mismatch_rejected',()=>{const badRelease=Buffer.from('Origin: Debian\nLabel: Debian\nSuite: noble\nVersion: 24.04\nCodename: noble\nSHA256:\n '+'a'.repeat(64)+' 42 main/binary-amd64/Packages\n'),b={...retained,releaseOutput:badRelease};rejects(()=>run(receipt(b),b));});
test('failure_incomplete_unknown_status_rejected',()=>{for(const value of ['[GNUPG:] NEWSIG\n[GNUPG:] NO_PUBKEY private\n','[GNUPG:] NEWSIG\n','[GNUPG:] UNKNOWN private\n']){const b={...retained,status:Buffer.from(value)};rejects(()=>run(receipt(b),b));}});
test('proxy_rejected_before_any_trap',()=>{let hits=0;const p=new Proxy(signedInput,{get(){hits++;throw Error('trap');},ownKeys(){hits++;throw Error('trap');},getPrototypeOf(){hits++;throw Error('trap');}}),b={...retained,signedInput:p};rejects(()=>run(receipt(),b));assert.equal(hits,0);});
test('shared_backing_rejected',()=>{const b={...retained,signedInput:Buffer.from(new SharedArrayBuffer(signedInput.length))};rejects(()=>run(receipt(b),b));});
test('subclass_and_decorated_buffers_rejected',()=>{class B extends Uint8Array{};Object.setPrototypeOf(B.prototype,Buffer.prototype);const sub=new B(4);for(const value of [sub,(()=>{const x=Buffer.from(signedInput);x.extra=1;return x;})()]){const b={...retained,signedInput:value};rejects(()=>run(receipt(b),b));}});
test('throwing_byteLength_buffer_length_getters_not_observed',()=>{for(const name of ['byteLength','buffer','length']){let hits=0;const x=Buffer.from(signedInput);Object.defineProperty(x,name,{configurable:true,get(){hits++;throw Error('getter');}});const b={...retained,signedInput:x};rejects(()=>run(receipt(),b));assert.equal(hits,0);}});
test('retained_container_getter_not_observed',()=>{let hits=0,b={...retained};Object.defineProperty(b,'signedInput',{enumerable:true,get(){hits++;return signedInput;}});rejects(()=>run(receipt(),b));assert.equal(hits,0);});
test('declaration_timeout_false_remains_not_runtime_proof',()=>{const o=run();assert.equal(o.gpgvCompletionDeclared,true);assert.equal(o.cryptographicVerification,false);assert.equal(o.sourceResourceClosureProven,false);});
test('release_scope_is_candidate_information_only',()=>{const o=run();assert.deepEqual(o.releaseCandidate.checksumEntryCounts,{MD5Sum:0,SHA1:0,SHA256:1,SHA512:0});assert.equal(o.releaseCandidate.releaseDateInformationalOnly,true);assert.equal(o.freshnessChecked,false);});
test('different valid Release body rejected even with repinned receipt',()=>{const changed=Buffer.from(release.toString('ascii').replace(' 42 main/',' 43 main/'));const b={...retained,releaseOutput:changed};rejects(()=>run(receipt(b),b));});
test('short signed body cannot claim larger retained Release',()=>{const b={...retained,signedInput:Buffer.from(signedInput.toString('ascii').replace(release.toString('ascii'),'short\n'))};rejects(()=>run(receipt(b),b));});
test('CRLF signed input corresponds to LF Release in narrow profile',()=>{const b={...retained,signedInput:Buffer.from(signedInput.toString('ascii').replace(/\n/g,'\r\n'))};const o=run(receipt(b),b);assert.equal(o.cleartextProfileCorresponds,true);assert.equal(o.cryptographicVerification,false);});
test('CRLF retained Release corresponds without authenticity',()=>{const b={...retained,releaseOutput:Buffer.from(release.toString('ascii').replace(/\n/g,'\r\n'))};const o=run(receipt(b),b);assert.equal(o.cleartextProfileCorresponds,true);assert.equal(o.trustedSigner,false);});
test('canonical text body relation never overrides nonproof flags',()=>{const o=run();assert.equal(o.cleartextProfileCorresponds,true);assert.equal(o.cryptographicVerification,false);assert.equal(o.sourceResourceClosureProven,false);});
console.log(JSON.stringify({kind:'foreground_probe_transcript_pure_spec',passed,failed,total:passed+failed,networkRequests:0,children:0,cryptographicEvidence:false}));if(failed)process.exitCode=1;
