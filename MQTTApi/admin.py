from django.contrib import admin
from .models import *
from guardian.admin import GuardedModelAdmin


admin.site.register(Device, GuardedModelAdmin)
admin.site.register(DeviceUnit, GuardedModelAdmin)
admin.site.register(TemperatureUnitValue, GuardedModelAdmin)
admin.site.register(SwitchUnitValue, GuardedModelAdmin)
admin.site.register(HumidityUnitValue, GuardedModelAdmin)
