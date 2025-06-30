"""
Configuration pour l'environnement de développement
Paramètres moins restrictifs pour faciliter le développement
"""

from .base import *

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

# Allowed hosts pour le développement
ALLOWED_HOSTS = ['localhost', '127.0.0.1', '0.0.0.0']

# Override security settings for development
SECURE_SSL_REDIRECT = False
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
SECURE_COOKIE_SECURE = False

# Email backend pour le développement (console)
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

# Database pour le développement
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db_dev.sqlite3',
        'OPTIONS': {
            'timeout': 20,
        }
    }
}

# Cache simple pour le développement
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.dummy.DummyCache',
    }
}

# CORS settings moins restrictifs pour le développement
CORS_ALLOW_ALL_ORIGINS = True
CORS_ALLOW_CREDENTIALS = True

# Logging pour le développement
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': True,
        },
        'galsecvote': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': True,
        },
        'audit': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': True,
        },
    },
}

# Debug Toolbar (optionnel)
if DEBUG:
    try:
        import debug_toolbar
        INSTALLED_APPS.append('debug_toolbar')
        MIDDLEWARE.insert(0, 'debug_toolbar.middleware.DebugToolbarMiddleware')
        INTERNAL_IPS = ['127.0.0.1', '::1']
    except ImportError:
        pass

# Settings de sécurité allégés pour le développement
PASSWORD_POLICY = {
    'MIN_LENGTH': 8,  # Plus court pour le dev
    'REQUIRE_UPPERCASE': False,
    'REQUIRE_LOWERCASE': False,
    'REQUIRE_DIGITS': False,
    'REQUIRE_SPECIAL_CHARS': False,
}

# Désactiver certaines sécurités pour le développement
TWO_FACTOR_AUTH = {
    'ENABLED': True,  # Garder activé pour tester
    'ENFORCE_FOR_ADMIN': False,  # Mais pas obligatoire
}

# Rate limiting plus permissif
REST_FRAMEWORK['DEFAULT_THROTTLE_RATES'] = {
    'anon': '1000/hour',
    'user': '10000/hour',
    'login': '100/min',
}

# Audit simplifié pour le développement
AUDIT_SETTINGS = {
    'LOG_AUTHENTICATION': True,
    'LOG_AUTHORIZATION': True,
    'LOG_DATA_ACCESS': False,  # Moins verbose
    'LOG_DATA_MODIFICATION': True,
    'LOG_SYSTEM_EVENTS': False,
    'LOG_SENSITIVE_ACTIONS': True,
}

# Static files pour le développement
STATICFILES_DIRS = [
    BASE_DIR / 'static',
]

# Créer les dossiers nécessaires
import os
os.makedirs(BASE_DIR / 'logs', exist_ok=True)
os.makedirs(BASE_DIR / 'media', exist_ok=True)
os.makedirs(BASE_DIR / 'static', exist_ok=True)