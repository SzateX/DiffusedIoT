from rest_framework import serializers
from rest_framework.fields import empty

from AuthServiceApp.models import *


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

    def create(self, validated_data):
        return RegisteredDevice.objects.create(**validated_data)


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('pk', 'username')


class GroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = Group
        fields = ('pk', 'name')


class UserDevicePermissionSerializer(serializers.ModelSerializer):
    device = serializers.SlugRelatedField(queryset=RegisteredDevice.objects.all(), slug_field='device_id')
    user = serializers.PrimaryKeyRelatedField(queryset=User.objects)
    read_permission = serializers.BooleanField()
    write_permission = serializers.BooleanField()

    def __init__(self, instance=None, data=empty, **kwargs):
        hub = None
        if 'hub' in kwargs:
            hub = kwargs.pop('hub')
        super(UserDevicePermissionSerializer, self).__init__(instance, data, **kwargs)
        if hub is not None:
            self.fields['device'].queryset = RegisteredDevice.objects.filter(hub=hub)

    class Meta:
        model = UserDevicePermission
        fields = ('pk', 'device', 'user', 'read_permission', 'write_permission')


class GroupDevicePermissionSerializer(serializers.ModelSerializer):
    device = serializers.SlugRelatedField(queryset=RegisteredDevice.objects.all(), slug_field='device_id')
    group = serializers.PrimaryKeyRelatedField(queryset=Group.objects)
    read_permission = serializers.BooleanField()
    write_permission = serializers.BooleanField()

    class Meta:
        model = GroupDevicePermission
        fields = ('pk', 'device', 'user', 'read_permission', 'write_permission')

    def __init__(self, instance=None, data=empty, **kwargs):
        hub = None
        if 'hub' in kwargs:
            hub = kwargs.pop('hub')
        super(GroupDevicePermissionSerializer, self).__init__(instance, data, **kwargs)
        if hub is not None:
            self.fields['device'].queryset = RegisteredDevice.objects.filter(hub=hub)

    class Meta:
        model = UserDevicePermission
        fields = ('pk', 'device', 'user', 'read_permission', 'write_permission')


class MeSerializer(serializers.ModelSerializer):
    groups = GroupSerializer(many=True)

    class Meta:
        model = User
        fields = ('pk', 'username', 'groups', 'is_staff')


class GroupPksSerializer(serializers.Serializer):
    pk = serializers.IntegerField()
