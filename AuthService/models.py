from django.db import models
from MQTTApi.enums import DeviceType, UnitDirection, UnitType
from rest_framework_api_key.models import AbstractAPIKey


# Create your models here.
class Hub(models.Model):
    private_address = models.GenericIPAddressField()
    public_address = models.GenericIPAddressField()


class HubAPIKey(AbstractAPIKey):
    organization = models.ForeignKey(
        Hub,
        on_delete=models.CASCADE,
        related_name="api_keys",
    )


class Device(models.Model):
    __TYPE_CHOICES = (
        (DeviceType.GENERIC_TEMPERATURE_SENSOR, 'Generic Temperature Sensor'),
        (DeviceType.GENERIC_HUMIDITY_SENSOR, 'Generic Humidity Sensor'),
        (DeviceType.GENERIC_LAMP, 'GL')
    )
    name = models.CharField(max_length=200)
    type_of_device = models.CharField(choices=__TYPE_CHOICES, max_length=200)
    hub = models.ForeignKey(Hub, on_delete=models.CASCADE, related_name='devices')


class DeviceUnit(models.Model):
    __DIRECTION_CHOICES = (
        (UnitDirection.INPUT, 'input'),
        (UnitDirection.OUTPUT, 'output'),
        (UnitDirection.IN_OUT, 'input/output')
    )
    __TYPE_CHOICES = (
        (UnitType.HUMIDITY_UNIT, 'Humidity Unit'),
        (UnitType.TEMPERATURE_UNIT, 'Temperature Unit'),
        (UnitType.SWITCH_UNIT, 'Switch Unit')
    )
    device = models.ForeignKey(Device, on_delete=models.CASCADE,
                               related_name='units',
                               max_length=200)
    direction = models.CharField(choices=__DIRECTION_CHOICES, max_length=200)
    type_of_unit = models.CharField(choices=__TYPE_CHOICES, max_length=200)