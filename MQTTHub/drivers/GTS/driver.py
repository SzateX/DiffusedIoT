import json

from django.utils import timezone

from MQTTApi.models import TemperatureUnitValue
from MQTTApi.enums import TemperatureUnit


def driver_function(data):
    temperature = data['temperature']
    return [TemperatureUnitValue(value=temperature, unit=TemperatureUnit.CELSIUS, timestamp=timezone.now())]


def incoming_function(value_obj):
    return {'data': {
        'temperature': value_obj.value
    }}