from rest_framework import serializers

from refactor.MQTTApi import Device


class DeviceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Device
        fields = ('pk', 'name', 'type_of_device')


