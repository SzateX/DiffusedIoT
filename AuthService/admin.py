from django.contrib import admin
from rest_framework_api_key.admin import APIKeyModelAdmin

from .models import *


@admin.register(HubAPIKey)
class HubAPIKeyModelAdmin(APIKeyModelAdmin):
    pass


# Register your models here.
admin.site.register(Device)
admin.site.register(DeviceUnit)
