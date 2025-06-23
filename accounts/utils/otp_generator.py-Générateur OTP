# Configuration GalSecVote - Environnement de développement
# ATTENTION : Ne jamais committer ce fichier avec des vraies valeurs de production !

# Django Settings
SECRET_KEY=your-very-secret-key-here-change-in-production
DEBUG=True
DJANGO_SETTINGS_MODULE=galsecvote.settings.development

# Base de données
DATABASE_URL=sqlite:///db_dev.sqlite3

# Email Configuration
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-app-password
DEFAULT_FROM_EMAIL=noreply@galsecvote.local

# Security
ADMIN_URL_PREFIX=secure-admin-dev
ADMIN_IP_WHITELIST=127.0.0.1,::1

# Encryption
MASTER_KEY=change-this-in-production-32-chars-minimum
RSA_KEY_SIZE=2048

# OTP Configuration
OTP_ISSUER=GalSecVote-Dev
OTP_LENGTH=6

# Cache
CACHE_URL=locmem://

# Logging
LOG_LEVEL=DEBUG

# Development specific
ALLOWED_HOSTS=localhost,127.0.0.1,0.0.0.0