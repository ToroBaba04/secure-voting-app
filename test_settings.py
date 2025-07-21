# test_settings.py
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
SECRET_KEY = 'test-key'
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

AUTH_USER_MODEL = 'accounts.User'
USE_TZ = True
STATIC_URL = '/static/'
MEDIA_URL = '/media/'