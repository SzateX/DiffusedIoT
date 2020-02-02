# Database
# https://docs.djangoproject.com/en/2.2/ref/settings/#databases
import os

from AuthService.settings import BASE_DIR

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
    }
}
