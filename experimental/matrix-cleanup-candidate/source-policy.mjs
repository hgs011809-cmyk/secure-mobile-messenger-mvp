// Pure source transformer only. No file writes, process launch, Matrix API or deployment.
import {createHash} from 'node:crypto';
export const BASE_IMAGE='matrixdotorg/synapse:v1.162.0@sha256:6b84a7bbac36f080b2d2e51e0289cf1b08b349598ea44a558df38d558f2c2311';
export const SOURCE_SHA256='6e995c5ddcc078f9ae099af8924ee2a2e40d2f5bf5349d148a1cfc7ad2030f2f';
export const ORIGINAL='hs.get_clock().looping_call(self._censor_redactions, Duration(minutes=5))';
export const CANDIDATE='hs.get_clock().looping_call_now(self._censor_redactions, Duration(seconds=30))';
export function prepareCandidate(source,{enabled=false,scope,baseImage}={}){
  if(enabled!==true||scope!=='github-actions-synthetic'||baseImage!==BASE_IMAGE)throw new Error('candidate_not_enabled');
  if(typeof source!=='string'||Buffer.byteLength(source)>20000||createHash('sha256').update(source).digest('hex')!==SOURCE_SHA256)throw new Error('source_not_pinned');
  if(source.indexOf(ORIGINAL)<0||source.indexOf(ORIGINAL)!==source.lastIndexOf(ORIGINAL)||source.includes(CANDIDATE))throw new Error('ambiguous_scheduler');
  const candidate=source.replace(ORIGINAL,CANDIDATE);
  if(candidate.replace(CANDIDATE,ORIGINAL)!==source)throw new Error('non_scheduler_change');
  return candidate;
}
