from rest_framework import serializers

from MQTTApi.models import Device, DeviceUnit


class DeviceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Device
        fields = ('pk', 'name', 'type_of_device')


class DeviceUnitSerializer(serializers.ModelSerializer):
    class Meta:
        model = DeviceUnit
        fields = ('pk', 'name', 'direction', 'type_of_unit')


