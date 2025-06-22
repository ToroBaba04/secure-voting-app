"""
Configuration Django pour GalSecVote
Système de vote électronique sécurisé - Configuration de développement
"""

import os
from pathlib import Path
from decouple import config
import secrets

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = config('SECRET_KEY', default='django-insecure-dev-key-change-in-production-' + secrets.token_urlsafe(20))

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = config('DEBUG', default=True, cast=bool)

ALLOWED_HOSTS = config('ALLOWED_HOSTS', default='localhost,127.0.0.1', cast=lambda x: x.split(','))

# Application definition
DJANGO_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
]

THIRD_PARTY_APPS = [
    'rest_framework',
    'corsheaders',
]

LOCAL_APPS = [
    'accounts',
    'vote',
    'cryptoutils',
    'dashboard',
    'audit',
]

INSTALLED_APPS = DJANGO_APPS + THIRD_PARTY_APPS + LOCAL_APPS

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    # Nos middlewares personnalisés seront ajoutés plus tard
    # 'audit.middleware.AuditMiddleware',
]

ROOT_URLCONF = 'galsecvote.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
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

WSGI_APPLICATION = 'galsecvote.wsgi.application'

# Database
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
        'OPTIONS': {
            'timeout': 20,
        }
    }
}

# Custom User Model
AUTH_USER_MODEL = 'accounts.User'

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {
            'min_length': 12 if not DEBUG else 8,  # Plus strict en production
        }
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Internationalization
LANGUAGE_CODE = 'fr-fr'
TIME_ZONE = 'Africa/Dakar'
USE_I18N = True
USE_TZ = True

# Static files (CSS, JavaScript, Images)
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_DIRS = [
    BASE_DIR / 'static',
]

# Media files
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# =============================================================================
# CONFIGURATION SÉCURISÉE POUR GALSECVOTE
# =============================================================================

# Session Security
SESSION_COOKIE_AGE = 1800  # 30 minutes
SESSION_SAVE_EVERY_REQUEST = True
SESSION_EXPIRE_AT_BROWSER_CLOSE = True

if not DEBUG:
    # Configuration HTTPS pour la production
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_SSL_REDIRECT = True
    SECURE_HSTS_SECONDS = 31536000
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True

# CSRF Protection
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = 'Strict'
CSRF_USE_SESSIONS = True

# Security Headers
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_BROWSER_XSS_FILTER = True
X_FRAME_OPTIONS = 'DENY'
SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'

# REST Framework configuration
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.SessionAuthentication',
        'rest_framework.authentication.TokenAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle'
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '100/hour' if DEBUG else '50/hour',
        'user': '1000/hour' if DEBUG else '500/hour',
        'login': '100/min' if DEBUG else '5/min',
        'vote': '10/hour',  # Limitation spéciale pour les votes
    },
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 20
}

# CORS Settings (pour le développement)
if DEBUG:
    CORS_ALLOW_ALL_ORIGINS = True
    CORS_ALLOW_CREDENTIALS = True
else:
    CORS_ALLOWED_ORIGINS = [
        "https://galsecvote.com",  # À adapter selon votre domaine
    ]

# =============================================================================
# CONFIGURATION SPÉCIFIQUE GALSECVOTE
# =============================================================================

# Configuration OTP (One-Time Password)
OTP_TOTP_ISSUER = 'GalSecVote'
OTP_LENGTH = 6
OTP_VALIDITY_PERIOD = 300  # 5 minutes

# Configuration de chiffrement
ENCRYPTION_SETTINGS = {
    'ALGORITHM': 'RSA',
    'KEY_SIZE': 2048,
    'PADDING': 'OAEP',
    'HASH_ALGORITHM': 'SHA256',
    'SIGNATURE_ALGORITHM': 'PSS',
}

# Configuration des tentatives de connexion
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = 900  # 15 minutes

# Configuration audit
AUDIT_SETTINGS = {
    'LOG_AUTHENTICATION': True,
    'LOG_AUTHORIZATION': True,
    'LOG_DATA_ACCESS': True,
    'LOG_DATA_MODIFICATION': True,
    'LOG_SYSTEM_EVENTS': True,
    'LOG_SENSITIVE_ACTIONS': True,
    'RETENTION_PERIOD': 2555,  # 7 ans en jours
}

# Email Configuration
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend' if DEBUG else 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = config('EMAIL_HOST', default='localhost')
EMAIL_PORT = config('EMAIL_PORT', default=587, cast=int)
EMAIL_USE_TLS = config('EMAIL_USE_TLS', default=True, cast=bool)
EMAIL_HOST_USER = config('EMAIL_HOST_USER', default='')
EMAIL_HOST_PASSWORD = config('EMAIL_HOST_PASSWORD', default='')
DEFAULT_FROM_EMAIL = config('DEFAULT_FROM_EMAIL', default='noreply@galsecvote.local')

# Logging Configuration
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {message}',
            'style': '{',
        },
        'security': {
            'format': '{asctime} [SECURITY] {levelname} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'level': 'DEBUG' if DEBUG else 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'verbose' if DEBUG else 'simple',
        },
        'file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': BASE_DIR / 'logs' / 'galsecvote.log',
            'formatter': 'verbose',
        },
        'security': {
            'level': 'WARNING',
            'class': 'logging.FileHandler',
            'filename': BASE_DIR / 'logs' / 'security.log',
            'formatter': 'security',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['console', 'file'] if not DEBUG else ['console'],
            'level': 'INFO',
            'propagate': True,
        },
        'galsecvote': {
            'handlers': ['console', 'file'],
            'level': 'DEBUG' if DEBUG else 'INFO',
            'propagate': True,
        },
        'audit': {
            'handlers': ['security', 'file'],
            'level': 'INFO',
            'propagate': False,
        },
        'security': {
            'handlers': ['security'],
            'level': 'WARNING',
            'propagate': False,
        },
    },
}

# Cache Configuration (simple pour le développement)
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache' if DEBUG else 'django.core.cache.backends.filebased.FileBasedCache',
        'LOCATION': BASE_DIR / 'cache' if not DEBUG else 'galsecvote-cache',
        'TIMEOUT': 300,
        'OPTIONS': {
            'MAX_ENTRIES': 1000,
        }
    }
}

# =============================================================================
# CRÉATION DES DOSSIERS NÉCESSAIRES
# =============================================================================

# Créer les dossiers nécessaires s'ils n'existent pas
import os
os.makedirs(BASE_DIR / 'logs', exist_ok=True)
os.makedirs(BASE_DIR / 'media', exist_ok=True)
os.makedirs(BASE_DIR / 'static', exist_ok=True)
if not DEBUG:
    os.makedirs(BASE_DIR / 'cache', exist_ok=True)

# =============================================================================
# CONFIGURATION DE DÉVELOPPEMENT SPÉCIALE
# =============================================================================

if DEBUG:
    # Autoriser tous les hosts en développement
    ALLOWED_HOSTS = ['*']
    
    # Installer Django Debug Toolbar si disponible
    try:
        import debug_toolbar
        INSTALLED_APPS.append('debug_toolbar')
        MIDDLEWARE.insert(0, 'debug_toolbar.middleware.DebugToolbarMiddleware')
        INTERNAL_IPS = ['127.0.0.1', '::1']
        
        DEBUG_TOOLBAR_CONFIG = {
            'DISABLE_PANELS': [
                'debug_toolbar.panels.redirects.RedirectsPanel',
            ],
            'SHOW_TEMPLATE_CONTEXT': True,
        }
    except ImportError:
        pass

# =============================================================================
# MESSAGES POUR LES DÉVELOPPEURS
# =============================================================================

if DEBUG:
    print("🚀 GalSecVote - Mode Développement")
    print(f"📁 BASE_DIR: {BASE_DIR}")
    print(f"🔑 SECRET_KEY: {SECRET_KEY[:20]}...")
    print(f"📧 EMAIL_BACKEND: {EMAIL_BACKEND}")
    print("⚠️  N'oubliez pas de créer votre fichier .env pour la configuration !")