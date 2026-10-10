# Experimental device/session prevention boundary

NOT production deployed, NOT complete Matrix messaging integration, NOT a security sign-off. Default broker/ingress is disabled. Existing production auth/app/NCP services are unchanged.

## Boundaries, not a universal callback

Pinned Synapse v1.162.0 supports `register_spam_checker_callbacks(check_login_for_spam=...)` before regular login device/access/refresh token persistence. `on_user_login` and authentication-provider post-login callbacks are too late. There is no exported universal `check_device_id` veto. Dehydrated devices, registration auto-login, refresh, appservice device creation, module registration and administrator impersonation do not all traverse the regular-login veto.

- `device_admission.py` uses the supported pre-login callback. Only an exact pending/active opaque user + fixed device + current enrolled identity is allowed. Missing/new IDs, changed fingerprints, revoked identities, absent/corrupt records are denied. A private synthetic operator bootstrap has one explicit tuple exemption. Revocation intents are read from a SEPARATE file and deny login while cleanup is pending. This is a lab `matrix.ci` module, not a general production plugin.
- Synapse has NO published ports in the admission fixture; only the inspected private internal bridge is reachable by the trusted job host. Administrator and broker paths stay private. JWT/SSO/appservice/MAS integrations are not configured; public/guest registration and MSC3814 dehydration are disabled.
- `client-ingress.mjs` is a default-deny **read-only staging ingress**: versions, own whoami/devices and sync GET only. ALL other paths/methods, public login/registration/refresh/get-token/dehydration/device writes/admin APIs, encoded-path ambiguity and credential query parameters are rejected before forwarding. It is NOT a full SDK-compatible gateway: message/key/SAS/room policy APIs deliberately remain closed until individually reviewed. No public listener is started automatically. CI explicitly binds it to loopback; production TLS/ACL/CORS and browser compatibility remain gates.
- Requests carry only a bearer Authorization header, never cookies/admin headers from the caller. Rate/concurrency/response-size bounds and revocation recheck before buffered response delivery are applied. This is not a comprehensive DDoS/traffic-hardening claim.

## Latest usable session, not one backend token row

A fresh enrolled P-256 proof renews the SAME Matrix user/device and preserves its device identity. Broker stores only a SHA-256 digest of the latest access token plus its conservative expiry. Ingress accepts that latest lease only. Older Synapse tokens can remain valid on the PRIVATE backend until their bounded lifetime expires; they are not publicly usable through ingress. We do not use logout to rotate because device/key continuity needs separate care. Native deactivation still invalidates all tokens on successful revocation. Do not claim all old token rows are deleted on every renewal.

## Coordinated revocation

`RevocationCoordinator` initializes from a dedicated `revocation-intents.json`, not `bridge-private.json`. It immediately denies in memory, persists intent BEFORE enrollment deletion/Matrix deactivation, and retains a permanent deny even if one cleanup fails. Grant callbacks and ingress use its deny-aware enrollment lookup. Restart restores pending denial; bounded internal/operator retries complete cleanup. Normal active devices have NO revocation intent and remain usable after restart. No public revocation route exists here. Scope is a single broker/store/coordinator process, not distributed consensus, forensic deletion or proven power-failure recovery.

## CI evidence requirements

`ci-policy.mjs` replaces the historical `ci.mjs` as the selected workflow entry point. It verifies fresh invite enrollment/P-256 proof, fixed identity after broker + coordinator restart, native extra/missing device denial, unchanged aggregate device/access/refresh token rows after rejected attempts, previous lease denial despite private native token validity, denied public mutation routes, coordinated native revocation, and simulated remote-cleanup failure with persistent deny/retry across coordinator restart. Node unit suite adds gateway URL/routing/error/rate/epoch tests and lease/lifecycle tests; ten native Synapse module tests run in the container.

Check the exact GitHub run before claiming new server tests pass. The 1 CPU/512 MiB fixture is NOT proof of safe cohosting on NCP's 1 GiB machine. Earlier 139.3 MiB one-instant observation and prior ~296s ciphertext cleanup remain independent samples, not new measurements of this change.

## Remaining rollout gates

Full key/SAS/message/room allowlist and negative rendering tests; actual browser cold message reopen; Android pair; HTTPS ingress and backend non-exposure on the intended deployment; upstream endpoint/version changes; serialized production enrollment/revocation wiring and bounded retry scheduling; deletion load/restarts/backups; resource/disk/current-service impact and explicit rollout approval. No existing safety code is treated as Matrix key verification.

Official source evidence:
- https://github.com/element-hq/synapse/blob/v1.162.0/synapse/rest/client/login.py#L455-L484
- https://github.com/element-hq/synapse/blob/v1.162.0/synapse/module_api/callbacks/spamchecker_callbacks.py#L936-L991
- https://github.com/element-hq/synapse/blob/v1.162.0/synapse/rest/client/devices.py#L451-L479
- https://github.com/element-hq/synapse/blob/v1.162.0/synapse/handlers/register.py#L860-L919
