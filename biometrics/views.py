import logging
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from .models import FaceData, WebAuthnCredential
from . import services

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


def start_fingerprint_enroll(request):
    # Generate a new challenge
    challenge = services.generate_challenge()

    # Build WebAuthn registration options
    options = PublicKeyCredentialCreationOptions(
        challenge=challenge,
        rp={"name": "MyApp"},
        user={
            "id": str(request.user.id),
            "name": request.user.username,
            "display_name": request.user.get_full_name(),
        },
        pub_key_cred_params=[{"type": "public-key", "alg": -7}],  # -7 = ES256
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification="preferred"
        ),
        attestation=AttestationConveyancePreference.DIRECT,
    )

    # Store challenge in session for verification later
    request.session['registration_challenge'] = challenge

    return render(request, 'biometrics/enroll_fingerprint.html', {'options': options})

@login_required
def complete_fingerprint_enroll(request):
    data = request.POST.dict()
    challenge = request.session.pop('registration_challenge', None)
    if not challenge:
        return JsonResponse({"ok": False, "error": "No challenge found"})

    try:
        verified = services.verify_registration_response(data, expected_challenge=challenge)
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
    credentials = WebAuthnCredential.objects.filter(user=request.user)
    options = PublicKeyCredentialRequestOptions(
        challenge=services.generate_challenge(),
        allow_credentials=[{"id": c.credential_id, "type": "public-key"} for c in credentials],
        user_verification="preferred",
    )
    request.session['auth_challenge'] = options.challenge
    return render(request, 'verify_fingerprint.html', {'options': options})


@login_required
def complete_fingerprint_verify(request):
    data = request.POST.dict()
    challenge = request.session.pop('auth_challenge', None)
    if not challenge:
        return JsonResponse({"ok": False, "error": "No challenge found"})

    credentials = WebAuthnCredential.objects.filter(user=request.user)
    try:
        verified = services.verify_authentication_response(
            data,
            expected_challenge=challenge,
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
