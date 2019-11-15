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


class RegisterDeviceSerializer(serializers.Serializer):
    hub = serializers.PrimaryKeyRelatedField()
    device_id = serializers.IntegerField()


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('pk', 'username')


class GroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = Group
        fields = ('pk', 'name')
