from django.contrib import admin
from rest_framework_api_key.admin import APIKeyModelAdmin

from AuthServiceApp.models import *

admin.site.register(RegisteredDevice)
admin.site.register(UserDevicePermission)
admin.site.register(GroupDevicePermission)

@admin.register(HubAPIKey)
class HubAPIKeyModelAdmin(APIKeyModelAdmin):
    pass
