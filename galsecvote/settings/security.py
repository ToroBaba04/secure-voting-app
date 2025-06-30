"""
Configuration de sécurité renforcée pour GalSecVote
Implémentation des exigences de sécurité selon les principes CIA
"""

from .base import *

# SECURITY SETTINGS

# Force HTTPS
SECURE_SSL_REDIRECT = True
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

# HSTS (HTTP Strict Transport Security)
SECURE_HSTS_SECONDS = 31536000  # 1 an
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

# Content Security Policy
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_BROWSER_XSS_FILTER = True
X_FRAME_OPTIONS = 'DENY'

# Cookie Security
SECURE_COOKIE_SECURE = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True

# Security Headers
SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'

# Security Middleware
SECURITY_MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'audit.middleware.SecurityHeadersMiddleware',  # Middleware personnalisé pour les headers
    'audit.middleware.RequestValidationMiddleware',  # Validation des requêtes
]

# Allowed Hosts (à configurer selon l'environnement)
ALLOWED_HOSTS = [
    'localhost',
    '127.0.0.1',
    'galsecvote.local',
]

# CORS Settings (restrictif pour la sécurité)
CORS_ALLOWED_ORIGINS = [
    "https://localhost:8000",
    "https://127.0.0.1:8000",
]

CORS_ALLOW_CREDENTIALS = True
CORS_ALLOWED_HEADERS = [
    'accept',
    'accept-encoding',
    'authorization',
    'content-type',
    'dnt',
    'origin',
    'user-agent',
    'x-csrftoken',
    'x-requested-with',
]

# Database Security
DATABASES['default'].update({
    'OPTIONS': {
        'timeout': 20,
        'check_same_thread': False,
        # Activation du WAL mode pour SQLite (meilleure sécurité)
        'init_command': "PRAGMA journal_mode=WAL;",
    }
})

# Admin Security
ADMIN_URL_PREFIX = config('ADMIN_URL_PREFIX', default='secure-admin-' + secrets.token_urlsafe(8))

# File Upload Security
FILE_UPLOAD_MAX_MEMORY_SIZE = 2621440  # 2.5 MB
DATA_UPLOAD_MAX_MEMORY_SIZE = 2621440  # 2.5 MB
DATA_UPLOAD_MAX_NUMBER_FIELDS = 100

# Allowed file extensions
ALLOWED_UPLOAD_EXTENSIONS = ['.pdf', '.jpg', '.jpeg', '.png']

# Rate Limiting
RATELIMIT_ENABLE = True
RATELIMIT_USE_CACHE = 'default'

# Cache Security (Redis recommandé pour la production)
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'galsecvote-cache',
        'TIMEOUT': 300,
        'OPTIONS': {
            'MAX_ENTRIES': 1000,
        }
    }
}

# Password Policy Enforcement
PASSWORD_POLICY = {
    'MIN_LENGTH': 12,
    'MAX_LENGTH': 128,
    'REQUIRE_UPPERCASE': True,
    'REQUIRE_LOWERCASE': True,
    'REQUIRE_DIGITS': True,
    'REQUIRE_SPECIAL_CHARS': True,
    'FORBIDDEN_PATTERNS': [
        'password', 'admin', 'user', 'galsecvote', 'vote', 'election'
    ],
    'PASSWORD_HISTORY_COUNT': 5,  # Ne pas réutiliser les 5 derniers mots de passe
}

# Account Lockout Policy
ACCOUNT_LOCKOUT = {
    'MAX_ATTEMPTS': 5,
    'LOCKOUT_DURATION': 900,  # 15 minutes
    'RESET_ATTEMPTS_AFTER': 3600,  # 1 heure
}

# Session Security
SESSION_SECURITY = {
    'WARN_AFTER': 1500,  # Avertir après 25 minutes d'inactivité
    'EXPIRE_AFTER': 1800,  # Expirer après 30 minutes d'inactivité
    'WARN_USER': True,
}

# Two-Factor Authentication
TWO_FACTOR_AUTH = {
    'ENABLED': True,
    'ENFORCE_FOR_ADMIN': True,
    'BACKUP_TOKENS_COUNT': 10,
    'TOKEN_VALIDITY': 300,  # 5 minutes
    'ISSUER_NAME': 'GalSecVote',
}

# Encryption Settings
ENCRYPTION_SETTINGS = {
    'ALGORITHM': 'RSA',
    'KEY_SIZE': 2048,
    'PADDING': 'OAEP',
    'HASH_ALGORITHM': 'SHA256',
    'SIGNATURE_ALGORITHM': 'PSS',
}

# Audit Configuration
AUDIT_SETTINGS = {
    'LOG_AUTHENTICATION': True,
    'LOG_AUTHORIZATION': True,
    'LOG_DATA_ACCESS': True,
    'LOG_DATA_MODIFICATION': True,
    'LOG_SYSTEM_EVENTS': True,
    'LOG_SENSITIVE_ACTIONS': True,
    'RETENTION_PERIOD': 2555,  # 7 ans en jours
    'ANONYMIZE_LOGS_AFTER': 365,  # 1 an
}

# IP Whitelist for Admin Access
ADMIN_IP_WHITELIST = config('ADMIN_IP_WHITELIST', default='127.0.0.1,::1', cast=lambda x: x.split(','))

# Security Headers
SECURITY_HEADERS = {
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Content-Security-Policy': (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    ),
}

# Intrusion Detection
INTRUSION_DETECTION = {
    'ENABLED': True,
    'MAX_REQUESTS_PER_MINUTE': 60,
    'SUSPICIOUS_PATTERNS': [
        r'<script',
        r'union\s+select',
        r'drop\s+table',
        r'--',
        r'/\*.*\*/',
    ],
    'BLOCK_DURATION': 3600,  # 1 heure
}

# API Security
API_SECURITY = {
    'REQUIRE_API_KEY': True,
    'API_KEY_HEADER': 'X-API-Key',
    'RATE_LIMIT_PER_USER': '100/hour',
    'RATE_LIMIT_PER_IP': '1000/hour',
}