import logging
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from .models import FaceData, WebAuthnCredential
from . import services
import json
from django.http import JsonResponse

from webauthn.helpers.structs import (
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions,
    AttestationConveyancePreference,
    AuthenticatorSelectionCriteria,
)

logger = logging.getLogger(__name__)

# ------------------ FACE AUTH ------------------

@login_required
def enroll_face(request):
    if request.method == "POST":
        img = request.FILES.get("face_image")
        if not img:
            return JsonResponse({"ok": False, "error": "No image uploaded"})

        # collect extra data
        fullname = request.POST.get("fullname")
        reg_no = request.POST.get("registration_number")
        dept = request.POST.get("department")
        level = request.POST.get("level")
        state = request.POST.get("state_of_origin")
        email = request.POST.get("email")
        phone = request.POST.get("phone_number")

        # detect face
        try:
            res = services.detect_face_from_file(img)
        except Exception as e:
            return JsonResponse({"ok": False, "error": str(e)})

        if not res or not res.get("faces"):
            return JsonResponse({"ok": False, "error": "No face detected"})

        token = res["faces"][0]["face_token"]

        FaceData.objects.update_or_create(
            user=request.user,
            defaults={
                "face_token": token,
                "fullname": fullname,
                "registration_number": reg_no,
                "department": dept,
                "level": level,
                "state_of_origin": state,
                "email": email,
                "phone_number": phone,
            },
        )
        return JsonResponse({"ok": True, "message": "Face enrolled with personal data!"})

    return render(request, "biometrics/enroll.html")



@login_required
def verify_face(request):
    if request.method == "POST":
        img = request.FILES.get("face_image")
        if not img:
            return JsonResponse({"ok": False, "error": "No image uploaded"})

        try:
            res = services.detect_face_from_file(img)
        except Exception as e:
            return JsonResponse({"ok": False, "error": str(e)})

        if not res.get("faces"):
            return JsonResponse({"ok": False, "error": "No face detected in live image"})

        live_token = res["faces"][0]["face_token"]

        try:
            saved = FaceData.objects.get(user=request.user)
        except FaceData.DoesNotExist:
            return JsonResponse({"ok": False, "error": "No enrolled face found"})

        cmp = services.compare_face_tokens(saved.face_token, live_token)
        confidence = cmp.get("confidence", 0)
        ok = confidence > 70

        if ok:
            # show personal data only if verification succeeds
            data = {
                "fullname": saved.fullname,
                "registration_number": saved.registration_number,
                "department": saved.department,
                "level": saved.level,
                "state_of_origin": saved.state_of_origin,
                "email": saved.email,
                "phone_number": saved.phone_number,
            }
            return JsonResponse({"ok": True, "confidence": confidence, "data": data})

        return JsonResponse({"ok": False, "confidence": confidence})

    return render(request, "biometrics/verify.html")



# ------------------- Fingerprint / WebAuthn Enrollment -------------------

import base64
import os
import json

def b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


@login_required
def start_fingerprint_enroll(request):
    challenge = services.generate_challenge()
    if isinstance(challenge, str):   # ✅ ensure it's bytes
        challenge = challenge.encode("utf-8")

    options = PublicKeyCredentialCreationOptions(
        challenge=challenge,
        rp={"name": "MyApp"},
        user={
            "id": str(request.user.id).encode("utf-8"),
            "name": request.user.username,
            "display_name": request.user.get_full_name() or request.user.username,
        },
        pub_key_cred_params=[{"type": "public-key", "alg": -7}],
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification="preferred"
        ),
        attestation=AttestationConveyancePreference.DIRECT,
    )

    # Store challenge in session (as base64 string)
    request.session['registration_challenge'] = base64.urlsafe_b64encode(challenge).decode()

    options_dict = {
        "challenge": request.session['registration_challenge'],
        "rp": {"name": "MyApp"},
        "user": {
            "id": base64.urlsafe_b64encode(str(request.user.id).encode()).decode(),
            "name": request.user.username,
            "displayName": request.user.get_full_name() or request.user.username,
        },
        "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
        "authenticatorSelection": {
            "userVerification": "preferred"
        },
        "attestation": "direct",
    }

    return render(request, 'biometrics/enroll_fingerprint.html', {
        "options": json.dumps(options_dict)
    })



@login_required
def complete_fingerprint_enroll(request):
    try:
        data = json.loads(request.body.decode("utf-8"))
    except Exception:
        return JsonResponse({"ok": False, "error": "Invalid JSON"})

    challenge = request.session.pop('registration_challenge', None)
    if not challenge:
        return JsonResponse({"ok": False, "error": "No challenge found"})

    challenge_bytes = base64.urlsafe_b64decode(challenge.encode())

    try:
        verified = services.verify_registration_response(
            data,
            expected_challenge=challenge_bytes
        )
    except Exception as e:
        return JsonResponse({"ok": False, "error": str(e)})

    if verified:
        WebAuthnCredential.objects.create(
            user=request.user,
            credential_id=verified.credential_id,
            public_key=verified.public_key,
            sign_count=verified.sign_count
        )
        return JsonResponse({"ok": True, "message": "Fingerprint enrolled!"})

    return JsonResponse({"ok": False, "error": "Enrollment failed"})


# ------------------- Fingerprint / WebAuthn Verification -------------------

@login_required
def start_fingerprint_verify(request):
    import base64
    credentials = WebAuthnCredential.objects.filter(user=request.user)
    challenge = services.generate_challenge()
    challenge_b64 = base64.urlsafe_b64encode(challenge).decode()

    request.session['auth_challenge'] = challenge_b64

    options_dict = {
        "challenge": challenge_b64,
        "allowCredentials": [
            {
                "id": base64.urlsafe_b64encode(c.credential_id).decode(),
                "type": "public-key"
            } for c in credentials
        ],
        "userVerification": "preferred",
    }

    return render(request, 'biometrics/verify_fingerprint.html', {
        "options": json.dumps(options_dict)
    })



@login_required
def complete_fingerprint_verify(request):
    try:
        data = json.loads(request.body.decode("utf-8"))
    except Exception:
        return JsonResponse({"ok": False, "error": "Invalid JSON"})

    challenge = request.session.pop('auth_challenge', None)
    if not challenge:
        return JsonResponse({"ok": False, "error": "No challenge found"})

    challenge_bytes = base64.urlsafe_b64decode(challenge.encode())
    credentials = WebAuthnCredential.objects.filter(user=request.user)

    try:
        verified = services.verify_authentication_response(
            data,
            expected_challenge=challenge_bytes,
            credential_public_keys={c.credential_id: c.public_key for c in credentials},
            sign_count_storage={c.credential_id: c.sign_count for c in credentials},
        )
    except Exception as e:
        return JsonResponse({"ok": False, "error": str(e)})

    if verified:
        cred = credentials.get(credential_id=verified.credential_id)
        cred.sign_count = verified.sign_count
        cred.save()
        return JsonResponse({"ok": True, "message": "Fingerprint verified!"})

    return JsonResponse({"ok": False, "error": "Verification failed"})












# import logging
# from django.shortcuts import render
# from django.contrib.auth.decorators import login_required
# from .models import FaceData
# from . import services
# # from webauthn.registration import generate_registration_options, verify_registration_response
# # from webauthn.authentication import generate_authentication_options, verify_authentication_response
# from .models import WebAuthnCredential
# from django.http import JsonResponse
# from webauthn import (
#     WebAuthnUser,
#     WebAuthnCredential,
#     WebAuthnRegistrationOptions,
#     WebAuthnRegistrationResponse,
#     WebAuthnAuthenticationOptions,
#     WebAuthnAuthenticationResponse
# )

# # from webauthn import (
# #     generate_authentication_options,
# #     verify_authentication_response,
# # )

# logger = logging.getLogger(__name__)
# @login_required
# def enroll_face(request):
#     if request.method == "POST":
#         img = request.FILES.get("face_image")
#         if not img:
#             return JsonResponse({"ok": False, "error": "No image uploaded"})

#         try:
#             res = services.detect_face_from_file(img)
#         except Exception as e:
#             return JsonResponse({"ok": False, "error": str(e)})

#         if not res or not res.get("faces"):
#             return JsonResponse({"ok": False, "error": "No face detected"})

#         token = res["faces"][0]["face_token"]
#         FaceData.objects.update_or_create(
#             user=request.user,
#             defaults={"face_token": token}
#         )
#         return JsonResponse({"ok": True, "message": "Face enrolled!"})

#     # GET request → just render template
#     return render(request, "biometrics/enroll.html")


# @login_required
# def verify_face(request):
#     if request.method == "POST":
#         img = request.FILES.get("face_image")
#         if not img:
#             return JsonResponse({"ok": False, "error": "No image uploaded"})

#         try:
#             res = services.detect_face_from_file(img)
#         except Exception as e:
#             return JsonResponse({"ok": False, "error": str(e)})

#         if not res.get("faces"):
#             return JsonResponse({"ok": False, "error": "No face detected in live image"})

#         live_token = res["faces"][0]["face_token"]

#         try:
#             saved = FaceData.objects.get(user=request.user)
#         except FaceData.DoesNotExist:
#             return JsonResponse({"ok": False, "error": "No enrolled face found"})

#         cmp = services.compare_face_tokens(saved.face_token, live_token)
#         confidence = cmp.get("confidence", 0)
#         ok = confidence > 70
#         return JsonResponse({
#             "ok": ok,
#             "confidence": confidence
#         })

#     return render(request, "biometrics/verify.html")


# @login_required
# def start_fingerprint_enroll(request):
#     options = generate_registration_options(user_id=str(request.user.id))
#     request.session['registration_challenge'] = options.challenge
#     return render(request, 'enroll_fingerprint.html', {'options': options})

# @login_required
# def complete_fingerprint_enroll(request):
#     data = request.POST
#     challenge = request.session.pop('registration_challenge')
#     verified = verify_registration_response(data, challenge)

#     if verified:
#         WebAuthnCredential.objects.create(
#             user=request.user,
#             credential_id=verified.credential_id,
#             public_key=verified.public_key,
#             sign_count=verified.sign_count
#         )
#         return JsonResponse({"ok": True, "message": "Fingerprint enrolled!"})
#     return JsonResponse({"ok": False, "error": "Enrollment failed"})


# from webauthn.helpers import generate_authentication_options, verify_authentication_response

# @login_required
# def start_fingerprint_verify(request):
#     credentials = WebAuthnCredential.objects.filter(user=request.user)
#     options = generate_authentication_options(credentials=[c.credential_id for c in credentials])
#     request.session['auth_challenge'] = options.challenge
#     return render(request, 'verify_fingerprint.html', {'options': options})

# @login_required
# def complete_fingerprint_verify(request):
#     data = request.POST
#     challenge = request.session.pop('auth_challenge')
#     credentials = WebAuthnCredential.objects.filter(user=request.user)

#     verified = verify_authentication_response(data, challenge, credentials)
#     if verified:
#         return JsonResponse({"ok": True, "message": "Fingerprint verified!"})
#     return JsonResponse({"ok": False, "error": "Verification failed"})
