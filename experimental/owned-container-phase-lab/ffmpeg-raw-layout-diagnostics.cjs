'use strict';
// SOURCE CANDIDATE ONLY. Adds bounded path-hierarchy observations to the
// unchanged raw-header reader. Zero issues do NOT admit an archive or build.
// No payload inflation, extraction, filesystem, process or network operation.
const {inspectRawZIPMetadata, LIMITS: RAW_LIMITS} = require('./ffmpeg-raw-zip-metadata.cjs');
const ERROR = 'INVALID_RAW_LAYOUT_DIAGNOSTICS';
const ISSUE_CODES = Object.freeze(['file_ancestor', 'ancestor_spelling_collision', 'implicit_parent']);
const LIMITS = Object.freeze({maxEntries: RAW_LIMITS.entries, maxDepth: RAW_LIMITS.depth,
  maxIssues: RAW_LIMITS.entries * RAW_LIMITS.depth * 2});

function inspectRawPathLayout(bytes) {
  try {
    // Only inspect entries produced by the trusted, private-copy header reader.
    // Never accept arbitrary caller-supplied metadata/getters as authoritative.
    const metadata = inspectRawZIPMetadata(bytes);
    const entries = metadata.entries;
    const explicit = new Map(entries.map((e, i) => [e.path.toLowerCase(), {entry: e, index: i}]));
    const spelling = new Map();
    const issues = [];
    const counts = {file_ancestor: 0, ancestor_spelling_collision: 0, implicit_parent: 0};
    function record(code, entryIndex, relatedEntryIndex, prefixDepth) {
      if (issues.length >= LIMITS.maxIssues) throw Error(ERROR);
      counts[code]++;
      issues.push(Object.freeze({code, entryIndex, relatedEntryIndex, prefixDepth}));
    }
    for (let i = 0; i < entries.length; i++) {
      const e = entries[i], parts = e.path.split('/');
      let prefix = '';
      for (let depth = 1; depth <= parts.length; depth++) {
        prefix = prefix ? prefix + '/' + parts[depth - 1] : parts[depth - 1];
        const key = prefix.toLowerCase(), first = spelling.get(key);
        if (!first) spelling.set(key, {text: prefix, index: i});
        else if (first.text !== prefix) record('ancestor_spelling_collision', i, first.index, depth);
        if (depth === parts.length) continue;
        const declared = explicit.get(key);
        if (!declared) record('implicit_parent', i, null, depth);
        else if (!declared.entry.directory) record('file_ancestor', i, declared.index, depth);
      }
    }
    return Object.freeze({kind: 'raw_zip_path_layout_diagnostics_only', sourceCandidateOnly: true,
      metadata, issues: Object.freeze(issues), counts: Object.freeze(counts),
      checkedEntries: entries.length, maxIssues: LIMITS.maxIssues,
      archiveAdmitted: false, fullOldPolicyAcceptanceEstablished: false,
      contentInflated: false, entriesMaterialized: false, payloadExecuted: false,
      vendorAuthenticated: false, buildOrSDKAdmitted: false});
  } catch { throw Error(ERROR); }
}
module.exports = Object.freeze({inspectRawPathLayout, ERROR, ISSUE_CODES, LIMITS});
