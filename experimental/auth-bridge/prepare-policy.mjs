import {appendFile} from 'node:fs/promises';
if(process.env.GITHUB_ACTIONS!=='true')throw new Error('ci_only');
await appendFile(new URL('../../infra/ncp/matrix-lab/ci/runtime/homeserver.yaml',import.meta.url),`
experimental_features:
  msc3814_enabled: false
modules:
  - module: device_admission.DeviceAdmissionGate
    config:
      enabled: true
      server_name: matrix.ci
      mapping_file: /data/bridge-private.json
      enrollment_file: /data/enrolment.json
      revocations_file: /data/revocation-intents.json
      operator_user: "@ci_bridge_operator:matrix.ci"
      operator_device: CI_OPERATOR
`);
