import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {prepareCandidate,BASE_IMAGE,ORIGINAL,CANDIDATE} from './source-policy.mjs';
// A temporary official-tag source or extracted pinned-image source is mandatory.
// Never read a running database, credential file or production source tree.
if(!process.env.SYNAPSE_CENSOR_SOURCE)throw new Error('public_source_fixture_required');
const source=readFileSync(process.env.SYNAPSE_CENSOR_SOURCE,'utf8');
const opt={enabled:true,scope:'github-actions-synthetic',baseImage:BASE_IMAGE};
test('default disabled',()=>assert.throws(()=>prepareCandidate(source),/candidate_not_enabled/));
test('requires exact opt-in',()=>assert.throws(()=>prepareCandidate(source,{...opt,enabled:1}),/candidate_not_enabled/));
test('rejects production scope',()=>assert.throws(()=>prepareCandidate(source,{...opt,scope:'production'}),/candidate_not_enabled/));
test('rejects tag-only image',()=>assert.throws(()=>prepareCandidate(source,{...opt,baseImage:'matrixdotorg/synapse:v1.162.0'}),/candidate_not_enabled/));
test('rejects modified source including authentication change',()=>assert.throws(()=>prepareCandidate(source.replace('original_event.internal_metadata.is_redacted()','True'),opt),/source_not_pinned/));
test('rejects duplicate scheduler',()=>assert.throws(()=>prepareCandidate(source+'\n'+ORIGINAL,opt),/source_not_pinned/));
test('rejects oversized source',()=>assert.throws(()=>prepareCandidate('x'.repeat(20001),opt),/source_not_pinned/));
test('changes only pinned scheduler, retains entire native censor body',()=>{const changed=prepareCandidate(source,opt);assert.equal(changed.replace(CANDIDATE,ORIGINAL),source);assert.equal(changed.split(CANDIDATE).length,2);assert.equal(changed.includes(ORIGINAL),false);});
test('refuses already modified candidate',()=>assert.throws(()=>prepareCandidate(prepareCandidate(source,opt),opt),/source_not_pinned/));
