from django.apps import AppConfig
from MQTTApi.mqtt_parser import mqtt_callback
from paho.mqtt.subscribe import callback


class MqttapiConfig(AppConfig):
    name = 'MQTTApi'

    def ready(self):
        super(MqttapiConfig, self).ready()
        callback(mqtt_callback, "inzynierkav2/listener", hostname="test.mosquitto.org")