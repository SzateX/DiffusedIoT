import json

from django.utils import timezone

from MQTTApi.enums import TemperatureUnit


def driver_function(models, unit, data):
    temperature = data['temperature']
    return [models.TemperatureUnitValue(value=temperature, unit=TemperatureUnit.CELSIUS, timestamp=timezone.now(), incoming=False, device_unit=unit)]


def incoming_function(value_obj):

    return {'data': {
        'temperature': float(value_obj.value) if not isinstance(value_obj, list) else float(value_obj[0].value)
    }}