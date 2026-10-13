'use strict';
// PRIVATE source candidate only. Combines trusted raw-header, path-layout, and
// extra-field observations over one bounded private snapshot. Never admission.
const util = require('node:util');
const crypto = require('node:crypto');
const {inspectRawPathLayout} = require('./ffmpeg-raw-layout-diagnostics.cjs');
const {inspectZipExtraFields} = require('./zip-extra-fields-diagnostics.cjs');
const ERROR = 'INVALID_RAW_HEADER_DIAGNOSTICS_COMPOSITION';
const MAX_ARCHIVE_BYTES = 2302701, MAX_EXTRA_BYTES = 262144, MAX_FIELDS = 4096, MAX_DIAGNOSTICS = 8192;
const typed = Object.getPrototypeOf(Uint8Array.prototype);
const intrinsicLength = Object.getOwnPropertyDescriptor(typed, 'length').get;
const intrinsicBuffer = Object.getOwnPropertyDescriptor(typed, 'buffer').get;
function fail() { throw Error(ERROR); }
function freezeDeep(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const key of Object.keys(value)) freezeDeep(value[key]);
    Object.freeze(value);
  }
  return value;
}
function inspectCombinedRawHeaders(input) {
  try {
    // Proxy is rejected before Buffer/prototype/property access. Length and
    // backing store come from intrinsic accessors; cap precedes ownKeys.
    if (util.types.isProxy(input) || !Buffer.isBuffer(input) || Object.getPrototypeOf(input) !== Buffer.prototype) fail();
    const n = intrinsicLength.call(input), backing = intrinsicBuffer.call(input);
    if (!Number.isSafeInteger(n) || n < 22 || n > MAX_ARCHIVE_BYTES || util.types.isSharedArrayBuffer(backing)) fail();
    for (const key of Reflect.ownKeys(input)) {
      if (typeof key === 'symbol' || !/^(0|[1-9][0-9]*)$/.test(key) || Number(key) >= n) fail();
    }
    const snapshot = Buffer.alloc(n);
    Uint8Array.prototype.set.call(snapshot, input);
    // Exactly one invocation of the existing combined metadata/layout reader.
    const layout = inspectRawPathLayout(snapshot);
    const metadata = layout.metadata;
    if (metadata.byteCount !== n || crypto.createHash('sha256').update(snapshot).digest('hex') !== metadata.observedArchiveSha256) fail();
    const entries = metadata.entries;
    if (entries.length !== metadata.entryCount || metadata.centralDirectoryOffset + metadata.centralDirectoryBytes > n) fail();
    let p = metadata.centralDirectoryOffset, totalExtra = 0, fields = 0, diagnosticCount = 0;
    const records = [];
    for (let i = 0; i < entries.length; i++) {
      const e = entries[i];
      if (p + 46 > n || snapshot.readUInt32LE(p) !== 0x02014b50) fail();
      const nameLen = snapshot.readUInt16LE(p + 28), extraLen = snapshot.readUInt16LE(p + 30), commentLen = snapshot.readUInt16LE(p + 32);
      if (nameLen + extraLen + commentLen + 46 > n - p || extraLen !== e.centralExtraBytes) fail();
      const localStart = e.dataStart - e.localExtraBytes;
      if (!Number.isSafeInteger(localStart) || localStart < e.localOffset + 30 || localStart + e.localExtraBytes !== e.dataStart || e.dataStart > metadata.centralDirectoryOffset) fail();
      totalExtra += extraLen + e.localExtraBytes;
      if (totalExtra > MAX_EXTRA_BYTES) fail();
      const local = inspectZipExtraFields(snapshot.subarray(localStart, e.dataStart), 'local');
      const centralStart = p + 46 + nameLen;
      const central = inspectZipExtraFields(snapshot.subarray(centralStart, centralStart + extraLen), 'central');
      fields += local.fieldCount + central.fieldCount;
      diagnosticCount += local.diagnostics.length + central.diagnostics.length;
      if (fields > MAX_FIELDS || diagnosticCount > MAX_DIAGNOSTICS || records.length >= 512) fail();
      records.push({entryIndex:i, local, central});
      p += 46 + nameLen + extraLen + commentLen;
    }
    if (p !== metadata.centralDirectoryOffset + metadata.centralDirectoryBytes || records.length !== metadata.entryCount) fail();
    return freezeDeep({kind:'combined_raw_header_diagnostics_only', sourceCandidateOnly:true,
      observedArchiveSha256:metadata.observedArchiveSha256, byteCount:n,
      oldPolicyHeaderReasons:metadata.oldPolicyHeaderReasons,
      layout:{issues:layout.issues, counts:layout.counts, checkedEntries:layout.checkedEntries},
      extras:{entries:records, totalExtraBytes:totalExtra, fieldCount:fields, diagnosticCount,
        maxExtraBytes:MAX_EXTRA_BYTES, maxFields:MAX_FIELDS, maxDiagnostics:MAX_DIAGNOSTICS},
      archiveAdmitted:false, fullOldPolicyAcceptanceEstablished:false, contentInflated:false,
      contentIntegrityChecked:false, entriesMaterialized:false, vendorAuthenticated:false, buildOrSDKAdmitted:false});
  } catch { throw Error(ERROR); }
}
module.exports = Object.freeze({inspectCombinedRawHeaders, ERROR, LIMITS:Object.freeze({maxArchiveBytes:MAX_ARCHIVE_BYTES,maxExtraBytes:MAX_EXTRA_BYTES,maxFields:MAX_FIELDS,maxDiagnostics:MAX_DIAGNOSTICS})});
