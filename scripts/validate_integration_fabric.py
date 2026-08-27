#!/usr/bin/env python3
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
targets = json.loads((ROOT / 'config/provisioning-targets.v2.json').read_text())
capabilities = json.loads((ROOT / 'config/integration-fabric-capabilities.v2.json').read_text())
assert len({target['id'] for target in targets['targets']}) == len(targets['targets'])
assert all(target['direct_n8n_access'] is False for target in targets['targets'])
assert all(value is False for key, value in capabilities.items() if key != 'schema_version')
for required in ('password','otp','reset_token','access_token','refresh_token','client_secret','private_key','provider_token'):
    assert required in targets['forbidden_payload_keys']
print('CODESTRA_PROVISIONING_FABRIC_V2=PASS')
