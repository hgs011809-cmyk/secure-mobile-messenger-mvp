// Synthetic CI worker. No logs, credentials or SDK exceptions leave this process.
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
const requireSdk = createRequire(new URL('../../../../experimental/matrix-client/package.json', import.meta.url));
for (const name of ['log', 'warn', 'error', 'info', 'debug', 'trace']) console[name] = () => {};
const sdk = await import(pathToFileURL(requireSdk.resolve('matrix-js-sdk')).href);
const noop = () => {};
const silent = { trace: noop, debug: noop, info: noop, warn: noop, error: noop, getChild: () => silent };
let client;
const wait = async (predicate, timeout = 90000) => {
    const end = Date.now() + timeout;
    while (Date.now() < end) {
        if (await predicate()) return;
        await new Promise(r => setTimeout(r, 250));
    }
    throw new Error('gate timeout');
};
const eventInRoom = (roomId, eventId) => client.getRoom(roomId)?.findEventById(eventId);
async function execute(op, args) {
    if (op === 'start') {
        client = sdk.createClient({ baseUrl: args.baseUrl, userId: args.user_id,
            accessToken: args.access_token, deviceId: args.device_id, logger: silent });
        await client.initRustCrypto({ useIndexedDB: false }); // Memory-only CI, never production.
        client.getCrypto().globalBlacklistUnverifiedDevices = true;
        client.getCrypto().setTrustCrossSignedDevices(false);
        await client.startClient({ initialSyncLimit: 100 });
        await wait(() => ['PREPARED', 'SYNCING'].includes(client.getSyncState()));
        return { userId: client.getUserId(), deviceId: client.getDeviceId(), keys: await client.getCrypto().getOwnDeviceKeys() };
    }
    if (op === 'verify') {
        const crypto = client.getCrypto();
        await wait(async () => {
            const devices = (await crypto.getUserDeviceInfo([args.userId], true)).get(args.userId);
            const device = devices?.get(args.deviceId);
            if (!device) return false;
            if (devices.size !== 1 || device.getFingerprint() !== args.keys.ed25519 || device.getIdentityKey() !== args.keys.curve25519)
                throw new Error('exact synthetic device mismatch');
            return true;
        });
        await crypto.setDeviceVerified(args.userId, args.deviceId, true);
        if (!(await crypto.getDeviceVerificationStatus(args.userId, args.deviceId))?.isVerified()) throw new Error('verification failed');
        return true;
    }
    if (op === 'create') {
        const result = await client.createRoom({ visibility: 'private', preset: 'private_chat',
            invite: [args.otherUser], creation_content: { 'm.federate': false },
            initial_state: [
                { type: 'm.room.encryption', state_key: '', content: { algorithm: 'm.megolm.v1.aes-sha2' } },
                { type: 'm.room.history_visibility', state_key: '', content: { history_visibility: 'joined' } },
                { type: 'm.room.join_rules', state_key: '', content: { join_rule: 'invite' } },
                { type: 'm.room.guest_access', state_key: '', content: { guest_access: 'forbidden' } },
            ], power_level_content_override: { users: { [client.getUserId()]: 100, [args.otherUser]: 0 },
                users_default: 0, events_default: 0, state_default: 100, invite: 100, kick: 100, ban: 100, redact: 0 },
        });
        return result.room_id;
    }
    if (op === 'join') { await client.joinRoom(args.roomId); return true; }
    if (op === 'ready') {
        await wait(() => client.getRoom(args.roomId)?.getJoinedMembers().length === 2);
        if (!(await client.getCrypto().isEncryptionEnabledInRoom(args.roomId))) throw new Error('not encrypted');
        return true;
    }
    if (op === 'send') return (await client.sendTextMessage(args.roomId, args.body)).event_id;
    if (op === 'decrypt') {
        await wait(async () => {
            const event = eventInRoom(args.roomId, args.eventId);
            if (!event) return false;
            await client.decryptEventIfNeeded(event);
            return !event.isDecryptionFailure() && event.getContent().body === args.body;
        });
        return true;
    }
    if (op === 'redact') {
        await client.redactEvent(args.roomId, args.eventId);
        return true;
    }
    if (op === 'deleted') {
        await wait(() => eventInRoom(args.roomId, args.eventId)?.isRedacted() === true);
        const event = eventInRoom(args.roomId, args.eventId);
        if (event.getContent().body !== undefined) throw new Error('plaintext remains in visible event');
        return true;
    }
    if (op === 'stop') { client?.stopClient(); return true; }
    throw new Error('unknown command');
}
process.on('message', async ({ id, op, args }) => {
    try { process.send({ id, ok: true, value: await execute(op, args) }); }
    catch { process.send({ id, ok: false }); }
});
process.on('disconnect', () => { try { client?.stopClient(); } finally { process.exit(0); } });
process.on('uncaughtException', () => process.exit(1));
process.on('unhandledRejection', () => process.exit(1));
