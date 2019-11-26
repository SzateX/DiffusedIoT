from rest_framework import serializers
from .models import *


class HubSerializer(serializers.ModelSerializer):
    class Meta:
        model = Hub
        fields = ('pk', 'name', 'private_address', 'public_address')


class HubApiKeySerializer(serializers.Serializer):
    api_key = serializers.CharField()


class HubApiKeyValidateSerialzier(serializers.Serializer):
    is_valid = serializers.BooleanField()
    hub_id = serializers.IntegerField()
    api_key = serializers.CharField()


class RegisterDeviceSerializer(serializers.Serializer):
    hub = serializers.PrimaryKeyRelatedField(queryset=Hub.objects)
    device_id = serializers.IntegerField()


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('pk', 'username')


class GroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = Group
        fields = ('pk', 'name')


class UserDevicePermissionSerializer(serializers.ModelSerializer):
    device = serializers.PrimaryKeyRelatedField(queryset=RegisteredDevice.objects)
    user = serializers.PrimaryKeyRelatedField(queryset=Group.objects)
    read_permission = serializers.BooleanField()
    write_permission = serializers.BooleanField()

    class Meta:
        model = UserDevicePermission
        fields = ('pk', 'device', 'user', 'read_permission', 'write_permission')


class GroupDevicePermissionSerializer(serializers.ModelSerializer):
    device = serializers.PrimaryKeyRelatedField(queryset=RegisteredDevice.objects)
    group = serializers.PrimaryKeyRelatedField(queryset=Group.objects)
    read_permission = serializers.BooleanField()
    write_permission = serializers.BooleanField()

    class Meta:
        model = GroupDevicePermission
        fields = ('pk', 'device', 'user', 'read_permission', 'write_permission')


class MeSerializer(serializers.ModelSerializer):
    groups = GroupSerializer(many=True)

    class Meta:
        model = User
        fields = ('pk', 'username', 'groups')