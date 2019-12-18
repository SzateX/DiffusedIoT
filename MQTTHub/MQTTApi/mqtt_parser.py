import json

from paho.mqtt import publish
from rest_framework.renderers import JSONRenderer

from MQTTApi.serializers import TemperatureUnitValueSerializer
from .models import Device, DeviceUnit, ConnectedUnit, TemperatureUnitValue
from .enums import DeviceType
from drivers.GTS.driver import driver_function
from drivers.GTS.driver import incoming_function

def mqtt_callback(client, userdata, message):
    obj = json.loads(message)
    if 'device' not in obj or 'unit' not in obj or 'data' in obj:
        return

    device = Device.objects.get(pk=obj['device'])
    unit = Device.objects.get(pk='unit', device=device)

    if unit.type_of_device == DeviceType.GENERIC_HUMIDITY_SENSOR:
        return
    elif unit.type_of_device == DeviceType.GENERIC_TEMPERATURE_SENSOR:
        objs = driver_function(obj['data'])
    elif unit.type_of_device == DeviceType.GENERIC_LAMP:
        return
    else:
        return

    prepared_objs = []

    for o in objs:
        saved_obj = o.save()
        if isinstance(saved_obj, TemperatureUnitValue):
            serializer_obj = JSONRenderer().render(TemperatureUnitValueSerializer(saved_obj).data)
            prepared_obj = {'data': serializer_obj,
                            'type': 'TemperatureUnitValue'}
            prepared_objs.append(JSONRenderer().render(prepared_obj))

    raise NotImplementedError("TODO - dokończenie dodania API")


def mqtt_incoming(unit_value):
    if isinstance(unit_value, TemperatureUnitValue):
        obj = incoming_function(unit_value)
    else:
        return
    unit_value.save()
    obj['device'] = unit_value.device_unit.device.pk
    obj['unit'] = unit_value.device_unit.pk

    s = json.dumps('obj')
    publish.single("inzynierkav2/sender", s, hostname="mqtt.eclipse.org")