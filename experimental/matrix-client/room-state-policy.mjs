// Validate authoritative room state without mutating it or SDK verification state.
export function validateBoundRoomState({room,roomId,state}){
  if(!room||typeof roomId!=='string'||!roomId||!Array.isArray(state)||state.length>512||state.some(e=>!e||typeof e.type!=='string'||!e.type||typeof e.state_key!=='string'||typeof e.event_id!=='string'||!e.event_id||Object.hasOwn(e,'room_id')&&e.room_id!==roomId))throw new Error('invalid_bound_room_state');
  const tuples=new Set();for(const e of state){const tuple=JSON.stringify([e.type,e.state_key]);if(tuples.has(tuple))throw new Error('invalid_bound_room_state');tuples.add(tuple);}
  const creation=state.find(e=>e.type==='m.room.create'&&e.state_key===''),current=room.currentState.getStateEvents('m.room.create','');
  if(!creation||creation.content?.['m.federate']!==false||creation.unsigned&&Object.hasOwn(creation.unsigned,'redacted_because')||current&&(current.isRedacted()||current.getId()!==creation.event_id))throw new Error('invalid_bound_room_creation');
}
