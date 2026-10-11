/** Browser-only Matrix v2 descriptor receipts. No transport, key persistence or logging.
 * Inputs are SDK-parsed JSON / trusted JavaScript, not hostile executable objects.
 * Browsers cannot reliably detect Proxy traps; proxies and malicious SDK objects
 * are outside this boundary. Own data properties reject ordinary accessors.
 * Await-boundary rechecks are fail-closed, NOT atomic race protection between the
 * last await and returning a receipt. A receipt is not continuing authorization.
 */
export class DescriptorReceiptError extends Error {
  constructor(code) { super(code); this.name='DescriptorReceiptError'; this.code=code; }
}
const fail=code=>{throw new DescriptorReceiptError(code);};
function plain(value,fields,code='INVALID_DESCRIPTOR') {
  if(!value||typeof value!=='object') fail(code);
  const proto=Object.getPrototypeOf(value);
  if(proto!==Object.prototype&&proto!==null) fail(code);
  const names=Reflect.ownKeys(value);
  if(names.length!==fields.length||fields.some(k=>!names.includes(k))) fail(code);
  const copy=Object.create(null);
  for(const k of fields) {
    const d=Object.getOwnPropertyDescriptor(value,k);
    if(!d||!Object.hasOwn(d,'value')) fail(code);
    copy[k]=d.value;
  }
  return copy;
}
function operations(value) {
  if(!Array.isArray(value)||Object.getPrototypeOf(value)!==Array.prototype||Reflect.ownKeys(value).length!==3) fail('INVALID_DESCRIPTOR');
  const a=Object.getOwnPropertyDescriptor(value,'0'),b=Object.getOwnPropertyDescriptor(value,'1'),l=Object.getOwnPropertyDescriptor(value,'length');
  if(!a||!b||!l||!Object.hasOwn(a,'value')||!Object.hasOwn(b,'value')||!Object.hasOwn(l,'value')||l.value!==2||!((a.value==='encrypt'&&b.value==='decrypt')||(a.value==='decrypt'&&b.value==='encrypt'))) fail('INVALID_DESCRIPTOR');
  return [a.value,b.value];
}
function copyCrypto(value) {
  const d=plain(value,['v','key','iv','hashes']);
  const k=plain(d.key,['kty','alg','ext','key_ops','k']);
  const h=plain(d.hashes,['sha256']);
  return {v:d.v,key:{kty:k.kty,alg:k.alg,ext:k.ext,key_ops:operations(k.key_ops),k:k.k},iv:d.iv,hashes:{sha256:h.sha256}};
}
function decode(value,size,url) {
  const pattern=url?/^[A-Za-z0-9_-]+$/:/^[A-Za-z0-9+/]+$/;
  if(typeof value!=='string'||value.length!==Math.ceil(size*8/6)||!pattern.test(value)) fail('INVALID_DESCRIPTOR');
  const standard=url?value.replace(/-/g,'+').replace(/_/g,'/'):value;
  const binary=atob(standard+'='.repeat((4-standard.length%4)%4));
  let canonical=btoa(binary).replace(/=+$/,'');
  if(url) canonical=canonical.replace(/\+/g,'-').replace(/\//g,'_');
  if(binary.length!==size||canonical!==value) fail('INVALID_DESCRIPTOR');
  return binary;
}
/** Same strict crypto subset as attachment-stream.validateDescriptor, without Node. */
export function validateFileDescriptor(value) {
  try {
    const d=copyCrypto(value),k=d.key;
    if(d.v!=='v2'||k.kty!=='oct'||k.alg!=='A256CTR'||k.ext!==true) fail('INVALID_DESCRIPTOR');
    decode(k.k,32,true);
    const iv=decode(d.iv,16,false);
    for(let i=8;i<16;i++) if(iv.charCodeAt(i)!==0) fail('INVALID_DESCRIPTOR');
    decode(d.hashes.sha256,32,false);
    return Object.freeze({v:'v2',key:Object.freeze({...k,key_ops:Object.freeze(['encrypt','decrypt'])}),iv:d.iv,hashes:Object.freeze({...d.hashes})});
  } catch { fail('INVALID_DESCRIPTOR'); }
}
function bounded(value,max) { return typeof value==='string'&&value.length>0&&value.length<=max&&!/[\x00-\x1f\x7f]/.test(value); }
function contentCopy(event) {
  // Other SDK message metadata is ignored, never trusted as descriptor input.
  const content=event.getContent();
  if(!content||typeof content!=='object') fail('INVALID_CONTENT');
  const values=Object.create(null);
  for(const k of ['msgtype','body','file']) {
    const p=Object.getOwnPropertyDescriptor(content,k);
    if(!p||!Object.hasOwn(p,'value')) fail('INVALID_CONTENT');
    values[k]=p.value;
  }
  if(values.msgtype!=='m.file'||!bounded(values.body,4000)) fail('INVALID_CONTENT');
  const file=plain(values.file,['v','key','iv','hashes','url'],'INVALID_CONTENT');
  // Standard bounded MXC reference; no URL dereference or transport here.
  if(!bounded(file.url,2048)||!/^mxc:\/\/(?:[A-Za-z0-9.-]+(?::[0-9]{1,5})?|\[[0-9A-Fa-f:]+\](?::[0-9]{1,5})?)\/[A-Za-z0-9_-]+$/.test(file.url)) fail('INVALID_CONTENT');
  const descriptor=copyCrypto({v:file.v,key:file.key,iv:file.iv,hashes:file.hashes});
  // Primitive checks prevent JSON.stringify from executing user toJSON methods.
  if(typeof descriptor.v!=='string'||typeof descriptor.iv!=='string'||typeof descriptor.key.kty!=='string'||typeof descriptor.key.alg!=='string'||typeof descriptor.key.ext!=='boolean'||typeof descriptor.key.k!=='string'||typeof descriptor.hashes.sha256!=='string') fail('INVALID_DESCRIPTOR');
  return {msgtype:values.msgtype,body:values.body,url:file.url,descriptor};
}
function context(conversation,event) {
  if(conversation.ready!==true) fail('NOT_INITIALIZED');
  const roomId=event.getRoomId(),eventId=event.getId(),senderUserId=event.getSender();
  if(!bounded(conversation.roomId,1024)||roomId!==conversation.roomId) fail('WRONG_ROOM');
  if(!bounded(eventId,1024)||!eventId.startsWith('$')) fail('INVALID_EVENT_ID');
  if(senderUserId!==conversation.peerUserId||!bounded(senderUserId,1024)||!bounded(conversation.peerDeviceId,255)) fail('WRONG_PEER');
  if(event.isRedacted()) fail('REDACTED');
  if(event.isEncrypted()!==true) fail('PLAINTEXT');
  if(event.isDecryptionFailure()!==false||event.getType()!=='m.room.message') fail('UNDECRYPTED');
  if(conversation.hiddenIds.has(eventId)) fail('DELETED');
  return {roomId,eventId,senderUserId,senderDeviceId:conversation.peerDeviceId};
}
/** Only event.getContent().file supplies crypto material; no caller trust flag. */
export async function receiveDescriptor(conversation,event) {
  try {
    const initial=context(conversation,event);
    const captured=contentCopy(event); // detached before the first await
    const contentIdentity=JSON.stringify(captured),contextIdentity=JSON.stringify(initial);
    const check=()=>{
      if(JSON.stringify(context(conversation,event))!==contextIdentity) fail('EVENT_CHANGED');
      if(JSON.stringify(contentCopy(event))!==contentIdentity) fail('CONTENT_CHANGED');
    };
    const gate=async()=>{
      try { await conversation.assertReceiveAllowed(event); }
      catch { fail('TRUST_DENIED'); }
      check();
    };
    const deletion=async()=>{
      let row;
      try { row=await conversation.ledger.get(initial.roomId,initial.eventId); }
      catch { fail('LEDGER_FAILED'); }
      check();
      if(row) fail('DELETED'); // all durable tombstone states deny receipt
    };
    await gate();
    const descriptor=validateFileDescriptor(captured.descriptor);
    await deletion();
    await gate();
    // Re-read durable deletion after the async trust gate, then refresh trust
    // again. Local hidden IDs/redaction/context/content are checked after each.
    await deletion();
    await gate();
    await deletion(); // final durable tombstone recheck after the last trust gate
    check();
    return Object.freeze({descriptor,...initial});
  } catch(error) {
    if(error instanceof DescriptorReceiptError) throw error;
    fail('RECEIPT_FAILED'); // never forward SDK exceptions or supplied values
  }
}
