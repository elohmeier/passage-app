# Verifies a registration and an assertion produced by Passkey.swift with py_webauthn,
# a server-side WebAuthn library. Usage: verify_webauthn.py <input.json>
import json, sys
from webauthn import verify_registration_response, verify_authentication_response
from webauthn.helpers import base64url_to_bytes

d = json.load(open(sys.argv[1]))
reg = verify_registration_response(
    credential=d["registration"],
    expected_challenge=base64url_to_bytes(d["registrationChallenge"]),
    expected_origin=d["origin"], expected_rp_id=d["rpId"], require_user_verification=True)
auth = verify_authentication_response(
    credential=d["authentication"],
    expected_challenge=base64url_to_bytes(d["authenticationChallenge"]),
    expected_origin=d["origin"], expected_rp_id=d["rpId"],
    credential_public_key=reg.credential_public_key, credential_current_sign_count=0, require_user_verification=True)
print(json.dumps({"ok": True, "backedUp": reg.credential_backed_up, "deviceType": str(reg.credential_device_type),
                  "userVerified": auth.user_verified, "aaguid": reg.aaguid}))
