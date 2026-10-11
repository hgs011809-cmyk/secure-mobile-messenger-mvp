// Test-only receipt bridge: SDK event -> private CI memory, never a public endpoint.
const transportExports=new Map();
async function transportExport({event}){
 const found=await descriptorFound(event);
 const receipt=await receiveDescriptor(requireConversation(),found);
 transportExports.set(event,JSON.stringify(receipt));
 return receipt;
}
async function transportAuthorityStatus({event}){
 const found=timelineEvent(event);
 if(!found||!transportExports.has(event))return {allowed:false,stage:'MISSING_RECEIPT'};
 try{
  const receipt=await receiveDescriptor(requireConversation(),found);
  const matches=JSON.stringify(receipt)===transportExports.get(event);
  return {allowed:matches,stage:matches?'LIVE':'RECEIPT_CHANGED'};
 }catch(error){
  const stage=['REDACTED','DELETED','TRUST_DENIED','WRONG_ROOM','WRONG_PEER','EVENT_CHANGED','CONTENT_CHANGED'].includes(error?.code)?error.code:'UNCLASSIFIED';
  return {allowed:false,stage};
 }
}
window.addEventListener('pagehide',()=>transportExports.clear());
