from rest_framework import serializers

from MQTTApi.models import Device, DeviceUnit, ConnectedUnit


class DeviceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Device
        fields = ('pk', 'name', 'type_of_device')


class DeviceUnitSerializer(serializers.ModelSerializer):
    class Meta:
        model = DeviceUnit
        fields = ('pk', 'name', 'direction', 'type_of_unit')


class ConnectedUnitSerializer(serializers.ModelSerializer):
    from_unit = serializers.PrimaryKeyRelatedField()

    class Meta:
        model = ConnectedUnit
        fields = ('pk', 'from_unit', 'dest_hub', 'dest_device', 'dest_unit')
