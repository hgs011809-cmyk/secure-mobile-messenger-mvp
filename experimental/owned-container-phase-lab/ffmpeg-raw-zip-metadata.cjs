'use strict';
// RAW ZIP32 HEADER OBSERVATIONS ONLY. Never inflates/decompresses, verifies
// entry content, materializes entries, authenticates a vendor or admits a build.
// Narrow old-policy compatibility reasons are observations, not relaxed gates.
const crypto=require('node:crypto'),util=require('node:util');
const ERROR='INVALID_RAW_ZIP_METADATA';
const LIMITS=Object.freeze({archiveBytes:2302701,entries:512,pathBytes:512,depth:16,fileBytes:8388608,declaredOutputBytes:33554432});
function bad(){throw Error(ERROR);}
const typed=Object.getPrototypeOf(Uint8Array.prototype),len=Object.getOwnPropertyDescriptor(typed,'length').get,back=Object.getOwnPropertyDescriptor(typed,'buffer').get;
function inspectRawZIPMetadata(bytes){try{
 if(util.types.isProxy(bytes)||!Buffer.isBuffer(bytes))bad();const n=len.call(bytes);if(n<22||n>LIMITS.archiveBytes||util.types.isSharedArrayBuffer(back.call(bytes)))bad();
 const b=Buffer.alloc(n);Uint8Array.prototype.set.call(b,bytes);const u16=o=>{if(!Number.isSafeInteger(o)||o<0||o+2>n)bad();return b.readUInt16LE(o);},u32=o=>{if(!Number.isSafeInteger(o)||o<0||o+4>n)bad();return b.readUInt32LE(o);};
 // Locate EOCD only where its declared comment ends at EOF; ambiguity rejected.
 const candidates=[];for(let o=n-22;o>=Math.max(0,n-22-65535);o--)if(u32(o)===0x06054b50&&o+22+u16(o+20)===n)candidates.push(o);
 if(candidates.length!==1)bad();const end=candidates[0],count=u16(end+10),cdSize=u32(end+12),cdOff=u32(end+16),commentBytes=u16(end+20);
 if(u16(end+4)||u16(end+6)||!count||count===65535||count>LIMITS.entries||u16(end+8)!==count||cdSize===0xffffffff||cdOff===0xffffffff||cdOff+cdSize!==end)bad();
 const reasons=new Set();if(commentBytes)reasons.add('old_policy_archive_comment');const entries=[],folded=new Set();let p=cdOff,totalC=0,totalU=0,previousEnd=0;
 for(let i=0;i<count;i++){
  if(p+46>end||u32(p)!==0x02014b50)bad();const madeBy=u16(p+4),needed=u16(p+6),flags=u16(p+8),method=u16(p+10),declaredCRC32=u32(p+16),cs=u32(p+20),us=u32(p+24),nl=u16(p+28),extra=u16(p+30),comment=u16(p+32),attr=u32(p+38),offset=u32(p+42);
  if(u16(p+34)||!nl||nl>LIMITS.pathBytes+1||p+46+nl+extra+comment>end||cs===0xffffffff||us===0xffffffff||offset===0xffffffff||cs>LIMITS.fileBytes||us>LIMITS.fileBytes)bad();
  const nameBytes=b.subarray(p+46,p+46+nl);for(const v of nameBytes)if(v<33||v>126)bad();const name=nameBytes.toString('ascii'),directory=name.endsWith('/'),normalized=directory?name.slice(0,-1):name,parts=normalized.split('/');
  if(!normalized||normalized.length>LIMITS.pathBytes||parts.length>LIMITS.depth||/[\\:]/.test(normalized)||parts.some(x=>!x||x==='.'||x==='..'||x.length>255||/[. ]$/.test(x))||folded.has(normalized.toLowerCase()))bad();folded.add(normalized.toLowerCase());
  if(offset<previousEnd||offset+30>cdOff||u32(offset)!==0x04034b50)bad();const localNeeded=u16(offset+4),localFlags=u16(offset+6),localMethod=u16(offset+8),localCRC=u32(offset+14),localCS=u32(offset+18),localUS=u32(offset+22),localNL=u16(offset+26),localExtra=u16(offset+28),dataStart=offset+30+localNL+localExtra,dataEnd=dataStart+cs;
  if(localNL!==nl||localFlags!==flags||localMethod!==method||localNeeded!==needed||dataEnd>cdOff||!b.subarray(offset+30,offset+30+localNL).equals(nameBytes))bad();
  if(!(flags&8)&&(localCRC!==declaredCRC32||localCS!==cs||localUS!==us))bad();
  // Descriptor bytes/extras are never interpreted as payload or trusted content.
  if(offset!==previousEnd)reasons.add('old_policy_noncontiguous_local_layout');if(flags&8)reasons.add('old_policy_data_descriptor');if(flags!==0&&flags!==0x800)reasons.add('old_policy_flags');if(method!==0&&method!==8)reasons.add('old_policy_method');if(madeBy!==0x0314||needed!==20)reasons.add('old_policy_version_host');if(extra||localExtra)reasons.add('old_policy_extra_fields');if(comment)reasons.add('old_policy_entry_comment');if(u16(p+36))reasons.add('old_policy_internal_attributes');if(u16(offset+10)!==u16(p+12)||u16(offset+12)!==u16(p+14))reasons.add('old_policy_timestamp_mismatch');
  const unixMode=attr>>>16,type=unixMode&0xf000,permissions=unixMode&0x0fff,low=attr&0xffff;if(type!==(directory?0x4000:0x8000)||(directory?permissions!==493:permissions!==420&&permissions!==493)||low!==(directory?16:0))reasons.add('old_policy_mode_or_type');
  if(directory&&(method!==0||cs!==0||us!==0||declaredCRC32!==0))reasons.add('old_policy_directory_payload');if(us>cs*100)reasons.add('old_policy_declared_ratio');
  totalC+=cs;totalU+=us;if(totalC>16777216||totalU>LIMITS.declaredOutputBytes)bad();previousEnd=dataEnd;
  entries.push(Object.freeze({path:normalized,directory,flags,method,declaredCRC32,declaredCompressedBytes:cs,declaredUncompressedBytes:us,unixMode,permissions,madeBy,needed,localOffset:offset,dataStart,dataEnd,centralExtraBytes:extra,localExtraBytes:localExtra,entryCommentBytes:comment}));p+=46+nl+extra+comment;
 }
 if(p!==end)bad();if(previousEnd!==cdOff)reasons.add('old_policy_local_tail_gap');
 return Object.freeze({kind:'raw_zip_header_observations_only',byteCount:n,observedArchiveSha256:crypto.createHash('sha256').update(b).digest('hex'),centralDirectoryOffset:cdOff,centralDirectoryBytes:cdSize,archiveCommentBytes:commentBytes,entryCount:count,declaredTotalCompressedBytes:totalC,declaredTotalUncompressedBytes:totalU,entries:Object.freeze(entries),oldPolicyHeaderReasons:Object.freeze([...reasons].sort()),oldFullValidatorInvoked:false,fullOldPolicyAcceptanceEstablished:false,contentInflated:false,contentIntegrityChecked:false,entryCRCCheckedAgainstContent:false,entriesMaterialized:false,vendorAuthenticated:false,buildOrSDKAdmitted:false,generalZIPCompatibility:false});
 }catch{throw Error(ERROR);}}
module.exports=Object.freeze({inspectRawZIPMetadata,LIMITS,ERROR});
