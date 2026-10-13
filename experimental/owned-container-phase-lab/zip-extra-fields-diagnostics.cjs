'use strict';
// Pure SOURCE CANDIDATE ONLY. Bounded analysis of a caller-supplied ZIP extra-field slice.
const util = require('node:util');
const ERROR = 'INVALID_ZIP_EXTRA_FIELD_DIAGNOSTICS';
const MAX_BYTES = 65535, MAX_FIELDS = 1024, MAX_DIAGNOSTICS = 2048;
const ISSUE_CODES = Object.freeze(['duplicate_id', 'malformed_timestamp', 'malformed_uid_gid', 'malformed_zip64']);
const typed = Object.getPrototypeOf(Uint8Array.prototype);
const typedLength = Object.getOwnPropertyDescriptor(typed, 'length').get;
const typedBuffer = Object.getOwnPropertyDescriptor(typed, 'buffer').get;
function invalid() { throw Error(ERROR); }
function freezeDeep(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const key of Object.keys(value)) freezeDeep(value[key]);
    Object.freeze(value);
  }
  return value;
}
function inspectZipExtraFields(extraBytes, context) {
  try {
    if (util.types.isProxy(extraBytes) || !Buffer.isBuffer(extraBytes) || Object.getPrototypeOf(extraBytes) !== Buffer.prototype) invalid();
    if (context !== 'local' && context !== 'central') invalid();
    const n = typedLength.call(extraBytes), backing = typedBuffer.call(extraBytes);
    if (!Number.isSafeInteger(n) || n > MAX_BYTES || util.types.isSharedArrayBuffer(backing)) invalid();
    for (const key of Reflect.ownKeys(extraBytes)) {
      if (typeof key === 'symbol' || !/^(0|[1-9][0-9]*)$/.test(key) || Number(key) >= n) invalid();
    }
    const bytes = Buffer.alloc(n);
    Uint8Array.prototype.set.call(bytes, extraBytes);
    const fields = [], diagnostics = [], seen = new Set();
    let p = 0;
    while (p < n) {
      if (fields.length >= MAX_FIELDS || diagnostics.length > MAX_DIAGNOSTICS || n - p < 4) invalid();
      const id = bytes.readUInt16LE(p), length = bytes.readUInt16LE(p + 2), data = p + 4, end = data + length;
      if (end > n) invalid();
      const duplicate = seen.has(id); seen.add(id);
      let kind = 'unknown', format = 'opaque';
      if (id === 0x0001) { kind = 'zip64_diagnostic_only'; format = length ? 'opaque_bytes' : 'empty'; if (length < 8 || length % 8 !== 0) diagnostics.push({code:'malformed_zip64', fieldIndex:fields.length, id}); }
      else if (id === 0x5455) {
        kind = 'extended_timestamp_diagnostic_only';
        if (length < 1) { format = 'malformed'; diagnostics.push({code:'malformed_timestamp',fieldIndex:fields.length,id}); }
        else {
          const flags = bytes[data]; format = 'flags_'+flags.toString(16).padStart(2,'0');
          const expected = 1 + ((flags & 1) ? 4 : 0) + (context === 'local' ? ((flags & 2) ? 4 : 0) + ((flags & 4) ? 4 : 0) : 0);
          if ((flags & ~7) !== 0 || length !== expected) diagnostics.push({code:'malformed_timestamp',fieldIndex:fields.length,id});
        }
      } else if (id === 0x7875) {
        kind = 'uid_gid_diagnostic_only';
        if (length < 3) { format = 'malformed'; diagnostics.push({code:'malformed_uid_gid',fieldIndex:fields.length,id}); }
        else {
          const version = bytes[data], uidLength = bytes[data+1];
          if (version !== 1 || uidLength < 1 || uidLength > 4 || length < 3 + uidLength) {
            format = 'malformed'; diagnostics.push({code:'malformed_uid_gid',fieldIndex:fields.length,id});
          } else {
            const gidLengthAt = data + 2 + uidLength;
            if (gidLengthAt >= end) { format = 'malformed'; diagnostics.push({code:'malformed_uid_gid',fieldIndex:fields.length,id}); }
            else { const gidLength = bytes[gidLengthAt]; format = 'version1_uidlen_'+uidLength+'_gidlen_'+gidLength;
              if (gidLength < 1 || gidLength > 4 || gidLengthAt + 1 + gidLength !== end) diagnostics.push({code:'malformed_uid_gid',fieldIndex:fields.length,id});
            }
          }
        }
      }
      if (duplicate) diagnostics.push({code:'duplicate_id',fieldIndex:fields.length,id});
      if (diagnostics.length > MAX_DIAGNOSTICS) invalid();
      fields.push({id, length, kind, format}); p = end;
    }
    return freezeDeep({kind:'zip_extra_field_diagnostics_only',sourceCandidateOnly:true,context,byteLength:n,fieldCount:fields.length,fields,diagnostics,
      maxBytes:MAX_BYTES,maxFields:MAX_FIELDS,maxDiagnostics:MAX_DIAGNOSTICS,
      archiveAdmitted:false,buildOrSDKAdmitted:false,fullOldPolicyAcceptanceEstablished:false,
      contentInflated:false,entriesMaterialized:false,vendorAuthenticated:false});
  } catch { throw Error(ERROR); }
}
module.exports = Object.freeze({inspectZipExtraFields,ERROR,ISSUE_CODES,LIMITS:Object.freeze({maxBytes:MAX_BYTES,maxFields:MAX_FIELDS,maxDiagnostics:MAX_DIAGNOSTICS})});
