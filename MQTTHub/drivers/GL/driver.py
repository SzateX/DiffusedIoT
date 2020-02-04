import json

from django.utils import timezone


def driver_function(models, unit, data):
    state = data['state']
    return [models.SwitchUnitValue(value=state, timestamp=timezone.now(), incoming=False, device_unit=unit)]


def incoming_function(value_obj):
    return {'data': {
        'state': bool(value_obj.value) if not isinstance(value_obj, list) else bool(value_obj[0].value)
    }}