import os

from django.core.management.utils import get_random_secret_key
secret = get_random_secret_key()

SETTINGS_DIR = os.path.join(os.path.abspath(os.path.dirname(__file__)), "MQTTHub", "secret_key.py")

with open(SETTINGS_DIR, 'w') as f:
    f.write("SECRET_KEY = '%s'" % secret)
