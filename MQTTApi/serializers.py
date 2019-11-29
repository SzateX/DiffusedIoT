from rest_framework import serializers

from MQTTApi.models import Device


class DeviceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Device
        fields = ('pk', 'name', 'type_of_device')


