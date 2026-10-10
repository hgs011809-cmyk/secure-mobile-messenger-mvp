// Experimental Matrix adapter. Not imported by the deployed P2P application.
// SDK device verification and signed enrollment/room provisioning are prerequisites.
export class EncryptedConversation {
  constructor({client,roomId,peerUserId,peerDeviceId,ledger,onUpdate=()=>{}}){
    if(!client||!roomId||!peerUserId||!peerDeviceId||!ledger)throw new Error('missing_conversation_binding');
    Object.assign(this,{client,roomId,peerUserId,peerDeviceId,ledger,onUpdate});
    this.messages=new Map();this.hiddenIds=new Set();this.ready=false;this.deleteJobs=new Map();this.acknowledgedDeletes=new Map();
  }
  async initialize(){await this.ledger.open();for(const row of await this.ledger.list(this.roomId))this.hiddenIds.add(row.eventId);this.ready=true;}
  async assertSendAllowed(){
    if(!this.ready)throw new Error('not_initialized');
    const room=this.client.getRoom(this.roomId),me=this.client.getUserId();
    if(!room||room.getMyMembership()!=='join')throw new Error('not_joined');
    const state=(type)=>room.currentState.getStateEvents(type,'')?.getContent();
    if(state('m.room.encryption')?.algorithm!=='m.megolm.v1.aes-sha2')throw new Error('encryption_required');
    if(state('m.room.history_visibility')?.history_visibility!=='joined')throw new Error('private_history_required');
    if(state('m.room.join_rules')?.join_rule!=='invite')throw new Error('invite_only_required');
    if(state('m.room.create')?.['m.federate']!==false)throw new Error('non_federated_room_required');
    const members=room.getJoinedMembers().map(m=>m.userId);
    if(members.length!==2||!members.includes(me)||!members.includes(this.peerUserId))throw new Error('two_participants_required');
    const crypto=this.client.getCrypto();if(!crypto)throw new Error('crypto_required');
    if(crypto.globalBlacklistUnverifiedDevices!==true)throw new Error('unverified_device_block_required');
    const devices=await crypto.getUserDeviceInfo([me,this.peerUserId],true);
    const mine=devices.get(me),theirs=devices.get(this.peerUserId);
    if(mine?.size!==1||!mine.has(this.client.getDeviceId())||theirs?.size!==1||!theirs.has(this.peerDeviceId))throw new Error('one_bound_device_per_participant_required');
    const verification=await crypto.getDeviceVerificationStatus(this.peerUserId,this.peerDeviceId);
    if(!verification?.isVerified())throw new Error('peer_device_verification_required');
  }
  assertDeleteAllowed(){
    const room=this.client.getRoom(this.roomId),me=this.client.getUserId();
    if(!room||room.getMyMembership()!=='join')throw new Error('not_joined');
    const members=room.getJoinedMembers().map(m=>m.userId);
    if(!members.includes(me)||members.some(id=>id!==me&&id!==this.peerUserId))throw new Error('conversation_binding_changed');
    // Redaction needs no new key exchange, peer approval or online peer.
    // The homeserver must independently enforce membership/redaction authority.
  }
  async send(body){
    if(typeof body!=='string'||!body.trim()||body.length>4000)throw new Error('invalid_message');
    await this.assertSendAllowed();
    // The SDK encrypts the room event. Never send via a plaintext fallback.
    return this.client.sendTextMessage(this.roomId,body);
  }
  async ingest(event){
    if(!this.ready)throw new Error('not_initialized');
    if(event.getRoomId()!==this.roomId)return;
    if(event.getType()==='m.room.redaction'){
      const target=event.getAssociatedId();if(target)await this.applyServerRedaction(target);return;
    }
    const id=event.getId();if(!id)return;
    if(event.isRedacted())await this.applyServerRedaction(id);
    const deletion=await this.ledger.get(this.roomId,id);
    if(deletion||this.hiddenIds.has(id)){this.messages.delete(id);this.onUpdate(this.snapshot());return;}
    // Incoming plaintext, undecrypted events and unsupported content are never rendered.
    if(!event.isEncrypted()||event.getType()!=='m.room.message'||event.isDecryptionFailure())return;
    if(![this.client.getUserId(),this.peerUserId].includes(event.getSender()))return;
    const content=event.getContent();if(content.msgtype!=='m.text'||typeof content.body!=='string')return;
    this.messages.set(id,{id,sender:event.getSender(),body:content.body,timestamp:event.getTs()});
    this.onUpdate(this.snapshot());
  }
  async applyServerRedaction(id){
    this.hiddenIds.add(id);this.acknowledgedDeletes.set(id,{});this.messages.delete(id);this.onUpdate(this.snapshot());
    await this.ledger.put(this.roomId,id,{status:'server_redacted'});
    this.messages.delete(id);this.onUpdate(this.snapshot());
    // This confirms logical redaction only, not database/WAL/backup cleanup.
  }
  async deleteForBoth(id){
    if(!this.ready)throw new Error('not_initialized');
    if(typeof id!=='string'||!id.startsWith('$'))throw new Error('invalid_event_id');
    if(this.deleteJobs.has(id))return this.deleteJobs.get(id);
    this.hiddenIds.add(id);this.messages.delete(id);this.onUpdate(this.snapshot());
    const job=(async()=>{
      const old=await this.ledger.get(this.roomId,id);
      if(old?.status==='server_redacted')return {status:'server_redacted',cleanup:'unconfirmed'};
      let response=this.acknowledgedDeletes.get(id);
      if(!this.acknowledgedDeletes.has(id)){
        await this.ledger.put(this.roomId,id,{status:'pending_server'});
        this.assertDeleteAllowed();
        // Stable transaction identity lets the homeserver deduplicate network retries.
        try{response=await this.client.redactEvent(this.roomId,id,'delete:'+this.roomId+':'+id,{});}
        catch(error){
          if(this.acknowledgedDeletes.has(id)||(await this.ledger.get(this.roomId,id))?.status==='server_redacted')return {status:'server_redacted',cleanup:'unconfirmed'};
          // Initial pending marker remains durable; no server success is claimed.
          throw error;
        }
        this.acknowledgedDeletes.set(id,response);
      }
      try{await this.ledger.put(this.roomId,id,{status:'server_redacted',redactionId:response?.event_id});}
      catch{return {status:'server_redacted',metadataPersistence:'failed',cleanup:'unconfirmed'};}
      return {status:'server_redacted',cleanup:'unconfirmed'};
    })().finally(()=>{this.deleteJobs.delete(id);this.onUpdate(this.snapshot());});this.deleteJobs.set(id,job);return job;
  }
  async retryPendingDeletes(){
    const results=[],failedEventIds=[];
    for(const row of await this.ledger.list(this.roomId))if(row.status==='pending_server'){
      try{results.push({eventId:row.eventId,...await this.deleteForBoth(row.eventId)});}
      catch{failedEventIds.push(row.eventId);}
    }
    return {results,failedEventIds};
  }
  snapshot(){return [...this.messages.values()].sort((a,b)=>a.timestamp-b.timestamp);}
  clearMemory(){this.messages.clear();this.onUpdate([]);}
}
