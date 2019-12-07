from django.contrib import admin
from MQTTApi.models import *

admin.site.register(Device)
admin.site.register(DeviceUnit)
admin.site.register(TemperatureUnitValue)
admin.site.register(SwitchUnitValue)
admin.site.register(HumidityUnitValue)
