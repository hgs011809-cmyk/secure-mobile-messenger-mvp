import test from 'node:test';
import assert from 'node:assert/strict';
import {safeDiagnostic} from './safe-diagnostic.mjs';
test('retains only fixed classification fields',()=>assert.deepEqual(safeDiagnostic({operation:'create',kind:'MatrixError',code:'M_BAD_JSON',httpStatus:400}),{operation:'create',kind:'MatrixError',code:'M_BAD_JSON',httpStatus:400}));
test('never copies arbitrary messages, stack or credentials',()=>{
 const marker='synthetic-private-marker';
 const sanitized=safeDiagnostic({operation:marker,kind:marker,code:marker,httpStatus:marker,message:marker,stack:marker,access_token:marker,keys:marker});
 assert.equal(JSON.stringify(sanitized).includes(marker),false);
 assert.deepEqual(Object.keys(sanitized),['operation','kind','code','httpStatus']);
});
test('null and out-of-range values fail closed',()=>{
 assert.deepEqual(safeDiagnostic(null),{operation:'OTHER',kind:'Other',code:'OTHER',httpStatus:null});
 for(const value of [0,99,600,Infinity,'400']) assert.equal(safeDiagnostic({httpStatus:value}).httpStatus,null);
});
