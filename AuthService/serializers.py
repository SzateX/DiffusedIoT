from rest_framework import serializers
from .models import *


class HubSerializer(serializers.ModelSerializer):
    class Meta:
        model = Hub
        fields = ('pk', 'private_address', 'public_address')


class HubApiKeySerializer(serializers.Serializer):
    api_key = serializers.CharField()


class HubApiKeyValidateSerialzier(serializers.Serializer):
    is_valid = serializers.BooleanField()
    hub_id = serializers.IntegerField()
    api_key = serializers.CharField()