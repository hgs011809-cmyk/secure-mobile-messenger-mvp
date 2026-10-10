"""CI-only supported Synapse pre-login veto. No universal device hook exists."""
import json
from pathlib import Path
from synapse.module_api import NOT_SPAM
from synapse.api.errors import Codes

class DeviceAdmissionGate:
    def __init__(self, config, api):
        self.enabled = config.get('enabled') is True
        self.mapping = Path(config['mapping_file'])
        self.enrollment = Path(config['enrollment_file'])
        self.revocations = Path(config['revocations_file'])
        self.operator = config.get('operator_user')
        self.operator_device = config.get('operator_device')
        api.register_spam_checker_callbacks(check_login_for_spam=self.check_login)

    @staticmethod
    def parse_config(config):
        # This module cannot be enabled against an arbitrary production namespace.
        if config.get('server_name') != 'matrix.ci':
            raise ValueError('lab_gate_config_invalid')
        return config

    async def check_login(self, user_id, device_id, initial_display_name, request_info, auth_provider_id):
        if not self.enabled:
            return Codes.FORBIDDEN
        # Synthetic operator bootstrap is private only; ingress never accepts this account.
        if user_id == self.operator and device_id == self.operator_device:
            return NOT_SPAM
        if not device_id:
            return Codes.FORBIDDEN
        try:
            mappings = json.loads(self.mapping.read_text())['mappings']
            devices = json.loads(self.enrollment.read_text())['devices']
            denied = json.loads(self.revocations.read_text())['mappings']
            for enrolled_id, m in mappings.items():
                if enrolled_id in denied:
                    continue
                d = devices.get(enrolled_id)
                if (m.get('status') in ('pending', 'active') and m.get('userId') == user_id
                    and m.get('matrixDeviceId') == device_id and d
                    and d.get('deviceId') == enrolled_id
                    and d.get('peerId') == m.get('peerId')
                    and d.get('fingerprint') == m.get('fingerprint')):
                    return NOT_SPAM
        except Exception:
            pass  # Never disclose record contents, paths or exception detail.
        return Codes.FORBIDDEN
