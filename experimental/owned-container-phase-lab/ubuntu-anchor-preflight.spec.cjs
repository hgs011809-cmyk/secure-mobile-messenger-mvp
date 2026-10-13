'use strict';
// Pure structural tests only. Synthetic packet/status buffers below are NOT
// cryptographic evidence. Never invokes run(), gpgv, subprocesses or network.
const assert=require('node:assert/strict');
const cp=require('node:child_process');
cp.spawn=()=>{throw Error('FORBIDDEN_SUBPROCESS_IN_PURE_SPEC');};
globalThis.fetch=()=>{throw Error('FORBIDDEN_NETWORK_IN_PURE_SPEC');};
const p=require('./ubuntu-anchor-preflight.cjs');
const timeout=setTimeout(()=>{console.log('pure_spec_deadline');process.exitCode=1;},55000);timeout.unref();
let passed=0,failed=0;
function test(name,f){try{f();passed++;console.log('ok '+name);}catch{failed++;console.log('not_ok '+name);}}
function reject(f,code='profile'){assert.throws(f,e=>e.message==='PREFLIGHT_BLOCKED'&&e.fixed===code);}
function packet(n=1,old=false){let header;if(old){header=n<256?Buffer.from([0x88,n]):Buffer.from([0x89,n>>8,n&255]);}else if(n<192)header=Buffer.from([0xc2,n]);else if(n<8384){const x=n-192;header=Buffer.from([0xc2,192+(x>>8),x&255]);}else{header=Buffer.alloc(6);header[0]=0xc2;header[1]=255;header.writeUInt32BE(n,2);}return Buffer.concat([header,Buffer.alloc(n,4)]);}
function crc(b){let x=0xb704ce;for(const v of b){x^=v<<16;for(let i=0;i<8;i++){x<<=1;if(x&0x1000000)x^=0x1864cfb;}x&=0xffffff;}const out=Buffer.alloc(3);out.writeUIntBE(x,0,3);return out.toString('base64');}
function armor(b,withCRC=false){const encoded=b.toString('base64'),lines=encoded.match(/.{1,64}/g)||[];return '\n'+lines.join('\n')+'\n'+(withCRC?'='+crc(b)+'\n':'');}
function clear(b=packet(),body='Origin: Ubuntu\n',withCRC=false){return Buffer.from('-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n'+body+'-----BEGIN PGP SIGNATURE-----\n'+armor(b,withCRC)+'-----END PGP SIGNATURE-----\n');}
const validDate='Thu, 25 Apr 2024 15:10:33 UTC';
function release(date=validDate){return Buffer.from('Origin: Ubuntu\nLabel: Ubuntu\nSuite: noble\nVersion: 24.04\nCodename: noble\n'+(date===null?'':'Date: '+date+'\n')+'SHA256:\n '+ 'a'.repeat(64)+' 42 main/binary-amd64/Packages\n');}
const goodStatus=Buffer.from('[GNUPG:] NEWSIG\n[GNUPG:] KEY_CONSIDERED '+ 'A'.repeat(40)+' 0\n[GNUPG:] GOODSIG '+ 'B'.repeat(16)+' SYNTHETIC PRIVATE UID SENTINEL\n[GNUPG:] VALIDSIG '+ 'A'.repeat(40)+' 2024-04-25 1714057833 0 4 0 1 10 01 '+ 'C'.repeat(40)+'\n');
for(const n of [1,191,192,255,256,8383,8384,16384])test('new_packet_length_'+n,()=>assert.equal(p.packetFraming(packet(n)).signaturePacketCount,1));
for(const n of [1,255,256,16384])test('old_packet_length_'+n,()=>assert.equal(p.packetFraming(packet(n,true)).signaturePacketCount,1));
test('eight_signatures',()=>assert.equal(p.packetFraming(Buffer.concat(Array.from({length:8},()=>packet()))).signaturePacketCount,8));
test('ninth_signature_rejected',()=>reject(()=>p.packetFraming(Buffer.concat(Array.from({length:9},()=>packet())))));
test('packet_body_over_cap',()=>reject(()=>p.packetFraming(packet(16385))));
test('packet_total_over_cap',()=>reject(()=>p.packetFraming(Buffer.concat(Array.from({length:8},()=>packet(16384))))));
test('empty_packet_stream',()=>reject(()=>p.packetFraming(Buffer.alloc(0))));
test('zero_body',()=>reject(()=>p.packetFraming(Buffer.from([0xc2,0]))));
test('truncated_header',()=>reject(()=>p.packetFraming(Buffer.from([0xc2]))));
test('truncated_two_octet_length',()=>reject(()=>p.packetFraming(Buffer.from([0xc2,192]))));
test('truncated_five_octet_length',()=>reject(()=>p.packetFraming(Buffer.from([0xc2,255,0,0]))));
test('truncated_body',()=>reject(()=>p.packetFraming(Buffer.from([0xc2,2,4]))));
test('trailing_garbage',()=>reject(()=>p.packetFraming(Buffer.concat([packet(),Buffer.from([0])]))));
test('new_partial_length',()=>reject(()=>p.packetFraming(Buffer.from([0xc2,224,4]))));
test('old_indeterminate_length',()=>reject(()=>p.packetFraming(Buffer.from([0x8b,4]))));
test('noncanonical_new_five_octet',()=>reject(()=>p.packetFraming(Buffer.from([0xc2,255,0,0,0,1,4]))));
test('noncanonical_old_two_octet',()=>reject(()=>p.packetFraming(Buffer.from([0x89,0,1,4]))));
test('noncanonical_old_four_octet',()=>reject(()=>p.packetFraming(Buffer.from([0x8a,0,0,0,1,4]))));
for(const tag of [1,3,4,5,6,8,9,11,13,18,20,63])test('unsupported_new_tag_'+tag,()=>reject(()=>p.packetFraming(Buffer.from([0xc0|tag,1,4]))));
for(const tag of [1,3,5,6,8,9,11,13,15])test('unsupported_old_tag_'+tag,()=>reject(()=>p.packetFraming(Buffer.from([0x80|(tag<<2),1,4]))));
test('canonical_armor',()=>assert.equal(p.decodeSignatureArmor(armor(packet())).signaturePacketCount,1));
test('canonical_crc24_armor',()=>assert.equal(p.decodeSignatureArmor(armor(packet(),true)).crc24Present,true));
test('crc_reference_vector',()=>assert.equal(crc(Buffer.from('123456789')),'Ic8C'));
test('bad_crc24',()=>reject(()=>p.decodeSignatureArmor(armor(packet())+'=AAAA\n')));
test('misplaced_crc',()=>reject(()=>p.decodeSignatureArmor('\n=AAAA\nwgEE\n')));
test('invalid_crc_delimiter',()=>reject(()=>p.decodeSignatureArmor(armor(packet())+'==AAA\n')));
test('invalid_base64_character',()=>reject(()=>p.decodeSignatureArmor('\nwgE!\n')));
test('noncanonical_padding_bits',()=>reject(()=>p.decodeSignatureArmor('\nwh==\n')));
test('padding_in_middle',()=>reject(()=>p.decodeSignatureArmor('\nwg==\nAAAA\n')));
test('missing_padding',()=>reject(()=>p.decodeSignatureArmor('\nwgE\n')));
test('excess_padding',()=>reject(()=>p.decodeSignatureArmor('\nwgEE====\n')));
test('armor_blank_data_line',()=>reject(()=>p.decodeSignatureArmor('\nwgEE\n\n')));
test('armor_line_over_76',()=>reject(()=>p.decodeSignatureArmor('\n'+'A'.repeat(80)+'\n')));
test('armor_unknown_header',()=>reject(()=>p.decodeSignatureArmor('Unknown: value\n'+armor(packet()))));
test('armor_duplicate_header',()=>reject(()=>p.decodeSignatureArmor('Version: a\nVersion: b\n'+armor(packet()))));
test('clearsign_profile_not_crypto',()=>{const r=p.clearSignedProfile(clear());assert.equal(r.signaturePacketCount,1);assert.equal(r.cryptographicVerification,false);assert.equal(r.exploitSafe,false);assert.equal(r.plaintextFileByteCap,1048576);});
test('clearsign_crlf',()=>assert.equal(p.clearSignedProfile(Buffer.from(clear().toString().replace(/\n/g,'\r\n'))).signaturePacketCount,1));
test('clearsign_dash_escape',()=>assert.equal(p.clearSignedProfile(clear(packet(),'- -literal\n')).cleartextBodyBytes,9));
test('clearsign_unescaped_dash',()=>reject(()=>p.clearSignedProfile(clear(packet(),'-literal\n'))));
test('clearsign_compressed_packet',()=>reject(()=>p.clearSignedProfile(clear(Buffer.from([0xc8,1,4])))));
test('clearsign_literal_packet',()=>reject(()=>p.clearSignedProfile(clear(Buffer.from([0xcb,1,4])))));
test('clearsign_ascii_only',()=>reject(()=>p.clearSignedProfile(clear(packet(),'é\n'))));
test('clearsign_size_cap',()=>reject(()=>p.clearSignedProfile(Buffer.alloc(1048577,65))));
test('clearsign_newline_expansion_cap',()=>reject(()=>p.clearSignedProfile(clear(packet(),'\n'.repeat(530000)))));
test('clearsign_trailing_bytes',()=>reject(()=>p.clearSignedProfile(Buffer.concat([clear(),Buffer.from('x')]))));
test('clearsign_bad_hash_profile',()=>reject(()=>p.clearSignedProfile(Buffer.from(clear().toString().replace('SHA512','MD5')))));
test('release_date_utc',()=>{const r=p.parseReleaseDate(validDate);assert.equal(r.releaseDateTimestamp,1714057833);assert.equal(r.freshnessChecked,false);assert.equal(r.releaseDateInformationalOnly,true);});
test('release_date_gmt',()=>assert.equal(p.parseReleaseDate(validDate.replace('UTC','GMT')).releaseDateTimestamp,1714057833));
test('release_date_single_digit_day',()=>assert.equal(p.parseReleaseDate('Mon, 1 Apr 2024 00:00:00 UTC').releaseDate,'Mon, 1 Apr 2024 00:00:00 UTC'));
test('release_date_leap_day',()=>assert.equal(p.parseReleaseDate('Thu, 29 Feb 2024 00:00:00 UTC').freshnessChecked,false));
for(const date of ['Thu, 31 Apr 2024 00:00:00 UTC','Wed, 29 Feb 2023 00:00:00 UTC','Fri, 25 Apr 2024 15:10:33 UTC','Thu, 25 Apr 2024 24:00:00 UTC','Thu, 25 Apr 2024 00:60:00 UTC','Thu, 25 Apr 2024 00:00:60 UTC','Thu, 25 Apr 2024 00:00:00 +0000','Thu, 00 Apr 2024 00:00:00 UTC'])test('invalid_date_'+date,()=>reject(()=>p.parseReleaseDate(date),'release_scope'));
test('release_scope_with_date',()=>{const r=p.releaseScope(release());assert.equal(r.expectedNobleScope,true);assert.equal(r.releaseDate,validDate);assert.equal(r.checksumChainVerified,false);});
test('release_missing_date',()=>reject(()=>p.releaseScope(release(null)),'release_scope'));
test('release_duplicate_date',()=>reject(()=>p.releaseScope(Buffer.concat([release(),Buffer.from('Date: '+validDate+'\n')])),'release_scope'));
test('release_wrong_suite',()=>reject(()=>p.releaseScope(Buffer.from(release().toString().replace('Suite: noble','Suite: noble-updates'))),'release_scope'));
test('status_redacts_uid_and_fingerprints',()=>{const r=p.statusProjection(goodStatus),s=JSON.stringify(r);assert.equal(r.verified,true);assert.equal(r.counts.VALIDSIG,1);assert.equal(r.signatureClasses.canonicalText,1);assert(!s.includes('SYNTHETIC'));assert(!s.includes('A'.repeat(40)));assert(!s.includes('B'.repeat(16)));});
test('status_known_failure',()=>{const r=p.statusProjection(Buffer.from('[GNUPG:] NEWSIG\n[GNUPG:] ERRSIG secret\n[GNUPG:] NO_PUBKEY secret\n'));assert.equal(r.verified,false);assert.equal(r.failureClasses.NO_PUBKEY,1);assert(!JSON.stringify(r).includes('secret'));});
test('status_unknown_profile',()=>reject(()=>p.statusProjection(Buffer.from('[GNUPG:] UNKNOWN secret\n')),'status_profile'));
test('status_incomplete_signature',()=>assert.equal(p.statusProjection(Buffer.from('[GNUPG:] NEWSIG\n')).verified,false));
test('cleanup_success_projection',()=>{const r=p.cleanupProjection({status:'prerequisite_probe_only_verified',cryptographicVerification:true},3,3);assert.equal(r.status,'prerequisite_probe_only_verified');assert.equal(r.fdCleanup.failed,0);});
test('cleanup_failure_preserves_crypto_fact',()=>{const original={status:'prerequisite_probe_only_verified',cryptographicVerification:true},r=p.cleanupProjection(original,3,2);assert.equal(r.status,'blocked');assert.equal(r.failureClass,'fd_cleanup');assert.equal(r.cryptographicVerification,true);assert.equal(original.status,'prerequisite_probe_only_verified');});
test('cleanup_child_unclosed_remains_unknown',()=>{const r=p.cleanupProjection({status:'blocked',failureClass:'child_unclosed',cryptographicVerification:false,childFailureObservation:{closed:false}},2,2);assert.equal(r.failureClass,'child_unclosed');assert.equal(r.childFailureObservation.closed,false);});
test('cleanup_prior_unclosed_preserved',()=>{const r=p.cleanupProjection({status:'blocked',failureClass:'child_unclosed',cryptographicVerification:false},2,1);assert.equal(r.priorFailureClass,'child_unclosed');assert.equal(r.cryptographicVerification,false);});
test('cleanup_invalid_counts',()=>reject(()=>p.cleanupProjection({},1,2)));
clearTimeout(timeout);console.log(JSON.stringify({kind:'ubuntu_anchor_pure_spec',passed,failed,total:passed+failed,realChildren:0,networkRequests:0,cryptographicEvidence:false}));if(failed)process.exitCode=1;
