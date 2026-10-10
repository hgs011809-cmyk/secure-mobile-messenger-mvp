import unittest
import tempfile
import json
from pathlib import Path
from device_admission import DeviceAdmissionGate
from synapse.module_api import NOT_SPAM
from synapse.api.errors import Codes

class Api:
    def register_spam_checker_callbacks(self, **kwargs):
        self.callback = kwargs['check_login_for_spam']

class GateTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.map = Path(self.tmp.name) / 'map.json'
        self.enroll = Path(self.tmp.name) / 'enroll.json'
        self.revocations = Path(self.tmp.name) / 'revocations.json'
        self.revocations.write_text('{"mappings":{}}')
        self.mapping = {'mappings': {'fixture': {'status':'active','userId':'@pilot_fixture:matrix.ci','matrixDeviceId':'FIXED','peerId':'fixture-peer','fingerprint':'fixture-fingerprint'}}}
        self.records = {'devices': {'fixture': {'deviceId':'fixture','peerId':'fixture-peer','fingerprint':'fixture-fingerprint'}}}
        self.save()
        self.gate = DeviceAdmissionGate({'enabled':True,'mapping_file':str(self.map),'enrollment_file':str(self.enroll),'revocations_file':str(self.revocations),'operator_user':'@ci_operator:matrix.ci','operator_device':'CI_OPERATOR'},Api())
    def save(self):
        self.map.write_text(json.dumps(self.mapping))
        self.enroll.write_text(json.dumps(self.records))
    async def check(self, user='@pilot_fixture:matrix.ci', device='FIXED'):
        return await self.gate.check_login(user,device,None,[],None)
    async def test_exact_enrolled_device_allowed(self):
        self.assertEqual(await self.check(),NOT_SPAM)
    async def test_new_or_missing_device_denied(self):
        for device in ['EXTRA',None,'']:
            self.assertEqual(await self.check(device=device),Codes.FORBIDDEN)
    async def test_other_account_denied(self):
        self.assertEqual(await self.check(user='@other:matrix.ci'),Codes.FORBIDDEN)
    async def test_revoked_mapping_or_enrollment_denied(self):
        self.mapping['mappings']['fixture']['status']='blocked'; self.save()
        self.assertEqual(await self.check(),Codes.FORBIDDEN)
        self.mapping['mappings']['fixture']['status']='active'; self.records['devices']={}; self.save()
        self.assertEqual(await self.check(),Codes.FORBIDDEN)
    async def test_changed_fingerprint_denied(self):
        self.records['devices']['fixture']['fingerprint']='changed'; self.save()
        self.assertEqual(await self.check(),Codes.FORBIDDEN)
    async def test_missing_or_invalid_store_denied(self):
        self.map.unlink(); self.assertEqual(await self.check(),Codes.FORBIDDEN)
        self.map.write_text('invalid'); self.assertEqual(await self.check(),Codes.FORBIDDEN)
    async def test_operator_exact_bootstrap_only(self):
        self.assertEqual(await self.check('@ci_operator:matrix.ci','CI_OPERATOR'),NOT_SPAM)
        self.assertEqual(await self.check('@ci_operator:matrix.ci','EXTRA'),Codes.FORBIDDEN)
    async def test_durable_revocation_intent_denied(self):
        self.revocations.write_text('{"mappings":{"fixture":{"cleanupPending":true}}}')
        self.assertEqual(await self.check(),Codes.FORBIDDEN)
    async def test_disabled_is_fail_closed(self):
        self.gate.enabled=False
        self.assertEqual(await self.check(),Codes.FORBIDDEN)
    def test_production_namespace_not_accepted(self):
        with self.assertRaises(ValueError):
            DeviceAdmissionGate.parse_config({'server_name':'production.example'})
