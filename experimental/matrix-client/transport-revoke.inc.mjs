stage='authenticated transport actual native revoked lease';
assert(await resolve(b.accessToken)===null);
const revokedStream=await transportSession.denialProbe({expectedCode:'AUTHORIZATION_DENIED'});
assert(revokedStream.code==='AUTHORIZATION_DENIED'&&revokedStream.plaintextCallbacks===0&&revokedStream.bytes===0&&await transportSession.checkPreserved());
transportGates.push('actual-native-revoked-current-lease-denies-cached-node-decryption');
const finalTransportCleanup=await transportSession.cleanup();
assert(finalTransportCleanup.namespacesRemoved&&finalTransportCleanup.receiverTombstoned&&finalTransportCleanup.physicalErasure===false);
transportFixtures.delete(activeFixture);
