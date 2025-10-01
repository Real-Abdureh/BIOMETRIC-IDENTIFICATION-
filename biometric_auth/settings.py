import os
from pathlib import Path
BASE_DIR = Path(__file__).resolve().parent.parent
SECRET_KEY = 'replace-this-in-production'
DEBUG = True
ALLOWED_HOSTS = ["*","127.0.0.1", "localhost", "10.232.137.50", ".serveo.net", ]
CSRF_TRUSTED_ORIGINS = [
    "https://*.ngrok-free.app",
    "https://*.ngrok-free.dev",
    "https://*.loca.lt",
    'https://*.serveo.net',
]


INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'accounts',
    'biometrics',
    'webauthn',
     "widget_tweaks",
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'biometric_auth.urls'

# Required WebAuthn settings
WEBAUTHN_RP_NAME = "Your App Name"          # e.g., "Smart Health Symptom Checker"
WEBAUTHN_RP_ID = "localhost"                # Or your domain for production
WEBAUTHN_ORIGIN = "http://localhost:8000"  # Use https in production / ngrok for mobile

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'biometric_auth.wsgi.application'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

AUTH_PASSWORD_VALIDATORS = []

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

STATIC_URL = '/static/'

# Face++ credentials: set these environment variables or paste values here for quick testing.
FACEPP_API_KEY = os.getenv('FACEPP_API_KEY', 'your_facepp_key_here')
FACEPP_API_SECRET = os.getenv('FACEPP_API_SECRET', 'your_facepp_secret_here')
