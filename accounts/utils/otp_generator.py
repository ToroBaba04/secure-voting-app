# 1. accounts/utils/otp_generator.py - Correction du fichier
"""
Générateur OTP pour l'authentification 2FA
"""
import pyotp
import secrets
import qrcode
import io
import base64
from django.conf import settings

def generate_secret():
    """Génère un secret TOTP"""
    return pyotp.random_base32()

def get_totp_uri(secret, account_name, issuer="GalSecVote"):
    """Génère l'URI TOTP pour QR code"""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=account_name, issuer_name=issuer)

def verify_token(secret, token):
    """Vérifie un token TOTP"""
    totp = pyotp.TOTP(secret)
    return totp.verify(token, valid_window=2)

def generate_backup_tokens(count=10):
    """Génère des tokens de récupération"""
    return [secrets.token_hex(8) for _ in range(count)]

# 2. accounts/utils/__init__.py - Fichier d'initialisation
"""
Utilitaires pour l'authentification
"""
# Pas d'import problématique ici

# 3. Correction temporaire des settings pour les tests
# Créer ce fichier : test_settings.py (à la racine du projet)

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

SECRET_KEY = 'django-test-key-for-unit-tests-only'
DEBUG = True
ALLOWED_HOSTS = ['*']

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',
    }
}

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'accounts',
    'vote', 
    'cryptoutils',
    'dashboard',
    'audit',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
]

ROOT_URLCONF = 'galsecvote.urls'
AUTH_USER_MODEL = 'accounts.User'
USE_TZ = True

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

# Configuration simple pour tests
EMAIL_BACKEND = 'django.core.mail.backends.locmem.EmailBackend'
PASSWORD_HASHERS = ['django.contrib.auth.hashers.MD5PasswordHasher']
CACHES = {'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}}

# Configuration GalSecVote pour tests
OTP_TOTP_ISSUER = 'GalSecVote'
OTP_LENGTH = 6
OTP_VALIDITY_PERIOD = 300

# Pas de static files problématiques
STATIC_URL = None
STATIC_ROOT = None
MEDIA_URL = None
MEDIA_ROOT = None