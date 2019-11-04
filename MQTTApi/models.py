from django.db import models

from MQTTApi.enums import TemperatureUnit, \
    HumidityUnit


class GenericUnitValue(models.Model):
    device_unit = models.IntegerField()
    timestamp = models.DateTimeField()
    incoming = models.BooleanField()

    class Meta:
        abstract = True


class SwitchUnitValue(GenericUnitValue):
    value = models.BooleanField()


class TemperatureUnitValue(GenericUnitValue):
    __UNIT_CHOICES = (
        (TemperatureUnit.CELSIUS, 'C'),
        (TemperatureUnit.KELVIN, 'K'),
        (TemperatureUnit.FAHRENHEIT, 'F')
    )
    value = models.DecimalField(decimal_places=2, max_digits=10)
    unit = models.CharField(choices=__UNIT_CHOICES, max_length=200)


class HumidityUnitValue(GenericUnitValue):
    __UNIT_CHOICES = (
        (HumidityUnit.PERCENTAGE, '%'),
        (HumidityUnit.GRAMS_PER_METER_SQUARED, 'g/m**3')
    )
    value = models.DecimalField(decimal_places=2, max_digits=10)
    unit = models.CharField(choices=__UNIT_CHOICES,
                            max_length=200)