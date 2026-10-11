import {prepareTransportFixture,attachTransportReceiver} from './transport-pipeline.mjs';
import {validateDescriptor} from '../media-transfer-lab/attachment-stream.mjs';
const transportFixtures=new Set(),transportGates=[];
// CDP structured clones lose freezing; detach/canonicalize/freeze the SDK reply.
const sealTransportReceipt=r=>Object.freeze({...r,descriptor:validateDescriptor(r.descriptor)});
async function assertTransportPreserved(session){const p=await session.checkPreserved();assert(p.sourcePreserved===true&&p.receiverPreserved===true&&p.quarantineEmpty===true);return true;}
