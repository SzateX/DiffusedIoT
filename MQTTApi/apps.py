from django.apps import AppConfig


class MqttapiConfig(AppConfig):
    name = 'MQTTApi'

    def ready(self):
        print("DUPA")
