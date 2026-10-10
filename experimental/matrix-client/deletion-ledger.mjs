// Persistent deletion metadata only. Never stores plaintext messages or crypto keys.
export class DeletionLedger {
  constructor({indexedDB=globalThis.indexedDB,name='direct-matrix-deletions-v1'}={}){this.indexedDB=indexedDB;this.name=name;this.db=null;this.openJob=null;}
  async open(){
    if(this.db)return;if(this.openJob)return this.openJob;
    if(!this.indexedDB)throw new Error('indexeddb_required');
    this.openJob=new Promise((resolve,reject)=>{
      const req=this.indexedDB.open(this.name,1);
      req.onupgradeneeded=()=>{const store=req.result.createObjectStore('deletions',{keyPath:['roomId','eventId']});store.createIndex('roomId','roomId');};
      req.onerror=()=>reject(new Error('deletion_store_unavailable'));
      req.onblocked=()=>reject(new Error('deletion_store_blocked'));
      req.onsuccess=()=>{this.db=req.result;this.db.onversionchange=()=>{this.db.close();this.db=null;};resolve();};
    }).finally(()=>{this.openJob=null;});return this.openJob;
  }
  requireDB(){if(!this.db)throw new Error('deletion_store_closed');return this.db;}
  get(roomId,eventId){return new Promise((resolve,reject)=>{const req=this.requireDB().transaction('deletions').objectStore('deletions').get([roomId,eventId]);req.onsuccess=()=>resolve(req.result);req.onerror=()=>reject(new Error('deletion_store_read_failed'));});}
  list(roomId){return new Promise((resolve,reject)=>{const req=this.requireDB().transaction('deletions').objectStore('deletions').index('roomId').getAll(roomId);req.onsuccess=()=>resolve(req.result);req.onerror=()=>reject(new Error('deletion_store_read_failed'));});}
  put(roomId,eventId,value){
    if(!['pending_server','server_redacted'].includes(value.status))throw new Error('invalid_deletion_status');
    const row={roomId,eventId,status:value.status};if(value.redactionId)row.redactionId=value.redactionId;
    return new Promise((resolve,reject)=>{const tx=this.requireDB().transaction('deletions','readwrite');tx.objectStore('deletions').put(row);tx.oncomplete=()=>resolve();tx.onerror=tx.onabort=()=>reject(new Error('deletion_store_write_failed'));});
  }
  close(){this.db?.close();this.db=null;}
}
