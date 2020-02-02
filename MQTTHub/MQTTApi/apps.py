from django.apps import AppConfig
import paho.mqtt.client as mqtt

from MQTTApi.mqtt_parser import mqtt_callback, set_models, set_serializers
from config import MQTT_BROKER
from paho.mqtt.subscribe import callback


class MqttapiConfig(AppConfig):
    name = 'MQTTApi'

    def ready(self):
        super(MqttapiConfig, self).ready()
        import MQTTApi.models as models
        import MQTTApi.serializers as serializers
        set_models(models)
        set_serializers(serializers)
        client = mqtt.Client()
        client.on_message = mqtt_callback
        client.on_connect = lambda c, userdata, flags, rc: c.subscribe("DiffusedIoT/listener")
        client.connect(MQTT_BROKER, 1883, 60)
        client.loop_start()
        # callback(mqtt_callback, "inzynierkav2/listener", hostname="test.mosquitto.org", userdata={'models': models})