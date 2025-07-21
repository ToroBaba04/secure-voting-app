# galsecvote/settings.py - Configuration Django pour GalSecVote (Version Corrigée)
"""
Configuration Django pour GalSecVote
Système de vote électronique sécurisé - Configuration de développement/production
"""

import os
from pathlib import Path
from decouple import config, Csv
import secrets

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# =============================================================================
# CONFIGURATION DE SÉCURITÉ
# =============================================================================

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = config('SECRET_KEY', default='django-insecure-dev-key-change-in-production-' + secrets.token_urlsafe(20))

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = config('DEBUG', default=True, cast=bool)

# Hosts autorisés - CORRECTION DU PROBLÈME
ALLOWED_HOSTS = config('ALLOWED_HOSTS', default='localhost,127.0.0.1', cast=Csv())

# =============================================================================
# APPLICATIONS DJANGO
# =============================================================================

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

# =============================================================================
# MIDDLEWARE
# =============================================================================

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    
    # Middlewares personnalisés GalSecVote
    'audit.middleware.AuditMiddleware',
    'audit.middleware.SecurityHeadersMiddleware',
]

ROOT_URLCONF = 'galsecvote.urls'

# =============================================================================
# TEMPLATES
# =============================================================================

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

# =============================================================================
# BASE DE DONNÉES
# =============================================================================

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
        'OPTIONS': {
            'timeout': 20,
        }
    }
}

# Configuration PostgreSQL pour production (décommenter si nécessaire)
# DATABASES = {
#     'default': {
#         'ENGINE': 'django.db.backends.postgresql',
#         'NAME': config('DB_NAME', default='galsecvote'),
#         'USER': config('DB_USER', default='galsecvote_user'),
#         'PASSWORD': config('DB_PASSWORD', default=''),
#         'HOST': config('DB_HOST', default='localhost'),
#         'PORT': config('DB_PORT', default='5432', cast=int),
#     }
# }

# Custom User Model
AUTH_USER_MODEL = 'accounts.User'

# =============================================================================
# VALIDATION DES MOTS DE PASSE
# =============================================================================

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {
            'min_length': 12 if not DEBUG else 8,
        }
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
    {
        'NAME': 'accounts.utils.password_validators.PasswordComplexityValidator',
    },
    {
        'NAME': 'accounts.utils.password_validators.PasswordStrengthValidator',
        'OPTIONS': {
            'min_strength': 3,
        }
    },
]

# =============================================================================
# INTERNATIONALISATION
# =============================================================================

LANGUAGE_CODE = 'fr-fr'
TIME_ZONE = 'Africa/Dakar'
USE_I18N = True
USE_TZ = True

# =============================================================================
# FICHIERS STATIQUES
# =============================================================================

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
# SÉCURITÉ DES SESSIONS
# =============================================================================

SESSION_COOKIE_AGE = config('SESSION_COOKIE_AGE', default=1800, cast=int)
SESSION_SAVE_EVERY_REQUEST = True
SESSION_EXPIRE_AT_BROWSER_CLOSE = True

# Configuration HTTPS (pour la production)
if not DEBUG:
    SESSION_COOKIE_SECURE = config('SESSION_COOKIE_SECURE', default=True, cast=bool)
    CSRF_COOKIE_SECURE = config('CSRF_COOKIE_SECURE', default=True, cast=bool)
    SECURE_SSL_REDIRECT = config('SECURE_SSL_REDIRECT', default=True, cast=bool)
    SECURE_HSTS_SECONDS = config('SECURE_HSTS_SECONDS', default=31536000, cast=int)
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

# =============================================================================
# CONFIGURATION GALSECVOTE SPÉCIFIQUE
# =============================================================================

# Configuration OTP (One-Time Password)
OTP_TOTP_ISSUER = config('OTP_TOTP_ISSUER', default='GalSecVote')
OTP_LENGTH = config('OTP_LENGTH', default=6, cast=int)
OTP_VALIDITY_PERIOD = config('OTP_VALIDITY_PERIOD', default=300, cast=int)

# Configuration de chiffrement
ENCRYPTION_SETTINGS = {
    'ALGORITHM': config('ENCRYPTION_ALGORITHM', default='RSA'),
    'KEY_SIZE': config('RSA_KEY_SIZE', default=2048, cast=int),
    'PADDING': 'OAEP',
    'HASH_ALGORITHM': config('HASH_ALGORITHM', default='SHA256'),
    'SIGNATURE_ALGORITHM': 'PSS',
}

# Configuration des tentatives de connexion
MAX_LOGIN_ATTEMPTS = config('MAX_LOGIN_ATTEMPTS', default=5, cast=int)
LOCKOUT_DURATION = config('LOCKOUT_DURATION', default=900, cast=int)

# Configuration audit
AUDIT_SETTINGS = {
    'LOG_AUTHENTICATION': config('LOG_AUTHENTICATION', default=True, cast=bool),
    'LOG_AUTHORIZATION': config('LOG_AUTHORIZATION', default=True, cast=bool),
    'LOG_DATA_ACCESS': config('LOG_DATA_ACCESS', default=True, cast=bool),
    'LOG_DATA_MODIFICATION': config('LOG_DATA_MODIFICATION', default=True, cast=bool),
    'LOG_SYSTEM_EVENTS': config('LOG_SYSTEM_EVENTS', default=True, cast=bool),
    'LOG_SENSITIVE_ACTIONS': True,
    'RETENTION_PERIOD': config('AUDIT_RETENTION_DAYS', default=2555, cast=int),
}

# =============================================================================
# CONFIGURATION EMAIL
# =============================================================================

EMAIL_BACKEND = config('EMAIL_BACKEND', default='django.core.mail.backends.console.EmailBackend')
EMAIL_HOST = config('EMAIL_HOST', default='localhost')
EMAIL_PORT = config('EMAIL_PORT', default=587, cast=int)
EMAIL_USE_TLS = config('EMAIL_USE_TLS', default=True, cast=bool)
EMAIL_HOST_USER = config('EMAIL_HOST_USER', default='')
EMAIL_HOST_PASSWORD = config('EMAIL_HOST_PASSWORD', default='')
DEFAULT_FROM_EMAIL = config('DEFAULT_FROM_EMAIL', default='GalSecVote <noreply@galsecvote.com>')

# =============================================================================
# REST FRAMEWORK
# =============================================================================

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
        'vote': '10/hour',
    },
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 20
}

# =============================================================================
# CORS SETTINGS
# =============================================================================

if DEBUG:
    CORS_ALLOW_ALL_ORIGINS = True
    CORS_ALLOW_CREDENTIALS = True
else:
    CORS_ALLOWED_ORIGINS = [
        "https://galsecvote.com",  # À adapter selon votre domaine
    ]

# =============================================================================
# CACHE
# =============================================================================

CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache' if DEBUG else 'django.core.cache.backends.filebased.FileBasedCache',
        'LOCATION': BASE_DIR / 'cache' if not DEBUG else 'galsecvote-cache',
        'TIMEOUT': config('CACHE_TIMEOUT', default=300, cast=int),
        'OPTIONS': {
            'MAX_ENTRIES': config('CACHE_MAX_ENTRIES', default=1000, cast=int),
        }
    }
}

# =============================================================================
# LOGGING
# =============================================================================

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
    },
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': BASE_DIR / 'logs' / 'galsecvote.log',
            'maxBytes': 1024*1024*15,  # 15MB
            'backupCount': 10,
            'formatter': 'verbose',
        },
        'console': {
            'level': 'DEBUG' if DEBUG else 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['file', 'console'],
            'level': 'INFO',
            'propagate': True,
        },
        'accounts': {
            'handlers': ['file', 'console'],
            'level': 'DEBUG' if DEBUG else 'INFO',
            'propagate': False,
        },
        'vote': {
            'handlers': ['file', 'console'],
            'level': 'DEBUG' if DEBUG else 'INFO',
            'propagate': False,
        },
        'audit': {
            'handlers': ['file', 'console'],
            'level': 'DEBUG' if DEBUG else 'INFO',
            'propagate': False,
        },
        'cryptoutils': {
            'handlers': ['file', 'console'],
            'level': 'DEBUG' if DEBUG else 'INFO',
            'propagate': False,
        },
    },
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
# CONFIGURATION DE DÉVELOPPEMENT
# =============================================================================

if DEBUG:
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
    print(f"🌐 ALLOWED_HOSTS: {ALLOWED_HOSTS}")
    print(f"📧 EMAIL_BACKEND: {EMAIL_BACKEND}")
    print("✅ Configuration chargée avec succès !")
    print("⚠️  N'oubliez pas de créer votre fichier .env pour la configuration personnalisée !")