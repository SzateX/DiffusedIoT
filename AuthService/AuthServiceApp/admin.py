from django.contrib import admin
from rest_framework_api_key.admin import APIKeyModelAdmin

from AuthServiceApp.models import *


@admin.register(HubAPIKey)
class HubAPIKeyModelAdmin(APIKeyModelAdmin):
    pass
