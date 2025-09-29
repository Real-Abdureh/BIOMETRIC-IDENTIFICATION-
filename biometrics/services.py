import requests
from django.conf import settings

# biometrics/services.py
import requests
import os
import base64

API_KEY = "wl4lxggwntUDuKNL4bVxJ-GL6HAX3Z0x"
API_SECRET = "j6adI51xTOHZmB5ISR4ylSjgHzfTUnlg"
FACEPP_URL = "https://api-us.faceplusplus.com/facepp/v3/detect"

def detect_face_from_file(img_file):
    files = {"image_file": img_file}
    data = {
        "api_key": API_KEY,
        "api_secret": API_SECRET,
    }
    res = requests.post(FACEPP_URL, data=data, files=files)
    return res.json()

def compare_face_tokens(token1, token2):
    url = "https://api-us.faceplusplus.com/facepp/v3/compare"
    data = {
        "api_key": API_KEY,
        "api_secret": API_SECRET,
        "face_token1": token1,
        "face_token2": token2,
    }
    res = requests.post(url, data=data)
    return res.json()


def generate_challenge(length=32):
    """
    Generate a random base64-encoded challenge for WebAuthn.
    """
    return base64.urlsafe_b64encode(os.urandom(length)).rstrip(b'=').decode('utf-8')
