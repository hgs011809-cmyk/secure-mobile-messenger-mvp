// Regression only: never broadens the existing SDK policy.
import test from 'node:test';
import assert from 'node:assert/strict';
import { authorizeSdkRequest } from '../auth-bridge/sdk-policy.mjs';
const devices=[{userId:'@a:fixture',matrixDeviceId:'A',ed25519:Buffer.alloc(32,1).toString('base64'),curve25519:Buffer.alloc(32,2).toString('base64')},{userId:'@b:fixture',matrixDeviceId:'B',ed25519:Buffer.alloc(32,3).toString('base64'),curve25519:Buffer.alloc(32,4).toString('base64')}];
const binding={roomId:'!pair:fixture',devices};
const identity={userId:devices[0].userId,matrixDeviceId:'A',deviceId:'bridge-a'};
const invoke=(method,target,body=null)=>authorizeSdkRequest({method,target,body,binding,identity});
for(const [name,method,target,body] of [
 ['legacy media upload','POST','/_matrix/media/v3/upload',{}],
 ['media config','GET','/_matrix/media/v3/config',null],
 ['authenticated media download','GET','/_matrix/client/v1/media/download/fixture/id',null],
 ['create media','POST','/_matrix/media/v1/create',{}],
 ['media overwrite','PUT','/_matrix/media/v3/upload/fixture/id',{}],
 ['TURN credentials','GET','/_matrix/client/v3/voip/turnServer',null],
 ['plaintext file','PUT','/_matrix/client/v3/rooms/!pair%3Afixture/send/m.room.message/tx',{msgtype:'m.file',body:'synthetic'}]
])test('unchanged ingress denies '+name,()=>assert.equal(invoke(method,target,body),null));
for(const type of ['m.call.invite','m.call.answer','m.call.candidates','m.call.hangup','org.matrix.msc3401.call.member']){
 test('unchanged ingress denies plaintext room '+type,()=>assert.equal(invoke('PUT','/_matrix/client/v3/rooms/!pair%3Afixture/send/'+type+'/tx',{}),null));
 test('unchanged ingress denies to-device '+type,()=>assert.equal(invoke('PUT','/_matrix/client/v3/sendToDevice/'+type+'/tx',{messages:{'@b:fixture':{B:{}}}}),null));
}
test('valid opaque encrypted event remains allowed: ingress cannot inspect its decrypted content',()=>{
 const body={algorithm:'m.megolm.v1.aes-sha2',device_id:'A',sender_key:devices[0].curve25519,session_id:Buffer.alloc(32,5).toString('base64'),ciphertext:Buffer.alloc(12,6).toString('base64')};
 assert.notEqual(invoke('PUT','/_matrix/client/v3/rooms/!pair%3Afixture/send/m.room.encrypted/tx',body),null);
 // Thus this test does NOT claim encrypted m.file/m.call semantic rejection or support.
});
