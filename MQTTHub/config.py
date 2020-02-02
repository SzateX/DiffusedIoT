# Database
# https://docs.djangoproject.com/en/2.2/ref/settings/#databases
import os
from MQTTHub.settings import BASE_DIR

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
    }
}

AUTH_SERVICE_ADDRESS = "http://127.0.0.1:8000/authService"
HUB_ID = 1
API_KEY = 'ADLLgMti.3Jsy2sCQnWs85bf8I0oPMmPSmNzEJRoT'
MQTT_BROKER = 'test.mosquitto.org'
