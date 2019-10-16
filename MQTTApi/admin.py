from django.contrib import admin
from .models import *
# Register your models here.

admin.register(Device)
admin.register(DeviceUnit)
admin.register(TemperatureUnit)
admin.register(SwitchUnitValue)
admin.register(HumidityUnitValue)