import {createClient,IndexedDBStore} from 'matrix-js-sdk';
import {DeletionLedger} from './deletion-ledger.mjs';
import {EncryptedConversation} from './conversation.mjs';
const silentLogger={trace(){},debug(){},info(){},warn(){},error(){},getChild(){return this;}};
// Development-only factory. Production admission/Matrix account mapping is NOT implemented.
export async function createLabClient({baseUrl,userId,deviceId,accessToken}){
  const url=new URL(baseUrl);
  if(url.protocol!=='http:'||!['127.0.0.1','localhost'].includes(url.hostname)||url.port!=='18008'||url.username||url.password)throw new Error('loopback_lab_only');
  if(!globalThis.indexedDB)throw new Error('indexeddb_required');
  if(!userId||!deviceId||!accessToken)throw new Error('local_test_session_required');
  const namespace=encodeURIComponent(userId+'|'+deviceId);
  const store=new IndexedDBStore({indexedDB:globalThis.indexedDB,dbName:'direct-matrix-lab-events-'+namespace});
  await store.startup();
  const client=createClient({baseUrl:url.origin,userId,deviceId,accessToken,store,logger:silentLogger,timelineSupport:true});
  await client.initRustCrypto({useIndexedDB:true,cryptoDatabasePrefix:'direct-matrix-lab-keys-'+namespace});
  const crypto=client.getCrypto();if(!crypto)throw new Error('crypto_initialization_failed');
  crypto.globalBlacklistUnverifiedDevices=true;
  // Tokens stay in memory. No localStorage token persistence or debug logging.
  return client;
}
export async function bindLabConversation({client,roomId,peerUserId,peerDeviceId,onUpdate}){
  const ledger=new DeletionLedger({name:'direct-matrix-lab-deletions-'+encodeURIComponent(client.getUserId()+'|'+client.getDeviceId())});
  const conversation=new EncryptedConversation({client,roomId,peerUserId,peerDeviceId,ledger,onUpdate});
  await conversation.initialize();
  // A future UI must wire live/decrypted timeline events and server redaction events,
  // clear memory on logout, and render textContent rather than untrusted HTML.
  return conversation;
}
