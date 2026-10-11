import test from 'node:test';
import assert from 'node:assert/strict';
import {validateBoundRoomState} from './room-state-policy.mjs';

const roomId='!bound:localhost';
const creation=()=>({type:'m.room.create',state_key:'',event_id:'$create',room_id:roomId,content:{'m.federate':false}});
const currentCreation=({redacted=false,id='$create'}={})=>({isRedacted:()=>redacted,getId:()=>id});
const roomWith=current=>({currentState:{getStateEvents:(type,key)=>{
  assert.equal(type,'m.room.create');assert.equal(key,'');return current;
}}});
const validate=(state,room=roomWith(currentCreation()))=>validateBoundRoomState({room,roomId,state});
const rejectsState=(state,room)=>assert.throws(()=>validate(state,room),{message:'invalid_bound_room_state'});
const rejectsCreation=(state,room)=>assert.throws(()=>validate(state,room),{message:'invalid_bound_room_creation'});

test('valid non-federated full state is accepted without mutation',()=>{
  const state=[creation(),{type:'m.room.encryption',state_key:'',event_id:'$encryption',room_id:roomId,content:{algorithm:'m.megolm.v1.aes-sha2'}}];
  const before=structuredClone(state);
  for(const event of state){Object.freeze(event.content);Object.freeze(event);}Object.freeze(state);
  assert.equal(validate(state),undefined);
  assert.deepEqual(state,before);
});

test('wrong room ID in creation or another state event is rejected',()=>{
  rejectsState([{...creation(),room_id:'!other:localhost'}]);
  rejectsState([creation(),{type:'m.room.name',state_key:'',event_id:'$name',room_id:'!other:localhost'}]);
});

test('missing room and malformed full state are rejected before current-state lookup',()=>{
  rejectsState([creation()],null);
  const room={currentState:{getStateEvents(){assert.fail('must not read current creation for invalid state');}}};
  for(const state of [undefined,null,{},'state',42,[null],[undefined],[false],[{}],
    [{...creation(),type:42}],[{...creation(),state_key:null}],[{...creation(),event_id:undefined}]]){
    rejectsState(state,room);
  }
});

test('512 state events are accepted but 513 are rejected',()=>{
  const state=[creation(),...Array.from({length:511},(_,i)=>({type:'m.room.member',state_key:'@user'+i+':localhost',event_id:'$member'+i}))];
  assert.doesNotThrow(()=>validate(state));
  rejectsState([...state,{type:'m.room.name',state_key:'',event_id:'$name'}]);
});

test('missing creation or anything other than literal m.federate false is rejected',()=>{
  rejectsCreation([]);
  rejectsCreation([{...creation(),type:'m.room.name'}]);
  rejectsCreation([{...creation(),state_key:'not-empty'}]);
  for(const content of [undefined,null,{}, {'m.federate':true},{'m.federate':'false'},{'m.federate':0},{'m.federate':null}]){
    rejectsCreation([{...creation(),content}]);
  }
});

test('redacted current creation is rejected even when its ID matches',()=>{
  rejectsCreation([creation()],roomWith(currentCreation({redacted:true})));
});

test('current creation event ID mismatch is rejected',()=>{
  rejectsCreation([creation()],roomWith(currentCreation({id:'$other-create'})));
});

test('absent current creation remains accepted',()=>{
  for(const current of [null,undefined])assert.doesNotThrow(()=>validate([creation()],roomWith(current)));
});

test('absent room ID is allowed but explicit malformed IDs fail closed',()=>{
  const absent=creation();delete absent.room_id;assert.doesNotThrow(()=>validate([absent]));
  for(const eventRoomId of [undefined,null,'',false,0])rejectsState([{...creation(),room_id:eventRoomId}]);
  rejectsState([{...creation(),event_id:''}],roomWith(currentCreation({id:''})));
  rejectsState([{...creation(),type:''}]);
  for(const bound of [undefined,null,'',false])assert.throws(()=>validateBoundRoomState({room:roomWith(null),roomId:bound,state:[creation()]}),{message:'invalid_bound_room_state'});
});

test('duplicate state tuples cannot hide conflicting or repeated creation policy',()=>{
  rejectsState([{...creation(),content:{'m.federate':true}},creation()]);
  rejectsState([creation(),{...creation(),event_id:'$later',content:{'m.federate':true}}]);
  rejectsState([creation(),creation()]);
  rejectsState([creation(),{type:'m.room.name',state_key:'',event_id:'$a'},{type:'m.room.name',state_key:'',event_id:'$b'}]);
});

test('raw creation redaction metadata fails closed even without current creation',()=>{
 for(const redacted_because of [{event_id:'$redaction'},null])rejectsCreation([{...creation(),unsigned:{redacted_because}}],roomWith(null));
});
