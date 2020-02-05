import json

from paho.mqtt import publish
from rest_framework.renderers import JSONRenderer
import paho.mqtt.client as mqtt

from MQTTApi.services import InternalApi, AuthServiceApi
from .enums import DeviceType
import drivers.GTS.driver
import drivers.GL.driver
from config import MQTT_BROKER

models = None
serializers = None


def mqtt_callback(client, userdata, message):
    global models
    global serializers
    print(message.payload)
    obj = json.loads(message.payload if not isinstance(message.payload, bytes) else message.payload.decode("UTF-8"))
    if 'device' not in obj or 'unit' not in obj or 'data' not in obj:
        return

    device = models.Device.objects.get(pk=obj['device'])
    unit = models.DeviceUnit.objects.get(pk=obj['unit'], device=device)

    if device.type_of_device == DeviceType.GENERIC_HUMIDITY_SENSOR:
        return
    elif device.type_of_device == DeviceType.GENERIC_TEMPERATURE_SENSOR:
        objs = drivers.GTS.driver.driver_function(models, unit, obj['data'])
    elif device.type_of_device == DeviceType.GENERIC_LAMP:
        objs = drivers.GL.driver.driver_function(models, unit, obj['data'])
    else:
        return

    prepared_objs = []

    for o in objs:
        o.save()
        if isinstance(o, models.TemperatureUnitValue):
            serializer_obj = json.dumps(serializers.TemperatureUnitValueSerializer(o).data)
            prepared_obj = {'data': serializer_obj,
                            'type': 'TemperatureUnitValue'}
            prepared_objs.append(json.dumps(prepared_obj))
        if isinstance(o, models.SwitchUnitValue):
            serializer_obj = json.dumps(serializers.SwitchUnitValueSerializer(o).data)
            prepared_obj = {'data': serializer_obj,
                            'type': 'SwitchUnitValue'}
            prepared_objs.append(json.dumps(prepared_obj))

    connected_units = models.ConnectedUnit.objects.filter(from_unit=unit)
    for connected_unit in connected_units:
        payload = {
            'device': connected_unit.dest_device,
            'unit': connected_unit.dest_unit,
            'data': prepared_objs
        }
        hub = AuthServiceApi.get_hub(connected_unit.dest_hub)
        InternalApi.send_data_to_unit(hub, payload)


def mqtt_incoming(device, unit, unit_values):
    global models
    global serializers

    print("mqtt_incoming")

    if device.type_of_device == DeviceType.GENERIC_TEMPERATURE_SENSOR:
        obj = drivers.GTS.driver.incoming_function(unit_values)
    elif device.type_of_device == DeviceType.GENERIC_LAMP:
        obj = drivers.GL.driver.incoming_function(unit_values)
    else:
        return

    try:
        for unit_value in unit_values:
            unit_value.save()
    except Exception as e:
        pass

    obj['device'] = device.pk
    obj['unit'] = unit.pk

    s = json.dumps(obj)
    client = mqtt.Client()

    client.connect(MQTT_BROKER, 1883, 60)
    client.publish('DiffusedIoT/sender', payload=s)
    client.disconnect()


def set_models(models_module):
    global models
    models = models_module


def set_serializers(serializer_module):
    global serializers
    serializers = serializer_module