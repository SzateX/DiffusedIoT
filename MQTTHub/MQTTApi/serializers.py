from rest_framework import serializers

from MQTTApi.models import Device, DeviceUnit, ConnectedUnit, \
    TemperatureUnitValue


class DeviceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Device
        fields = ('pk', 'name', 'type_of_device')


class DeviceUnitSerializer(serializers.ModelSerializer):
    class Meta:
        model = DeviceUnit
        fields = ('pk', 'name', 'direction', 'type_of_unit')


class ConnectedUnitSerializer(serializers.ModelSerializer):
    from_unit = serializers.PrimaryKeyRelatedField(queryset=DeviceUnit.objects)

    class Meta:
        model = ConnectedUnit
        fields = ('pk', 'from_unit', 'dest_hub', 'dest_device', 'dest_unit')


class ConnectedUnitSaveSerializer(serializers.Serializer):
    from_unit = serializers.IntegerField()
    dest_hub = serializers.IntegerField()
    dest_device = serializers.IntegerField()
    dest_unit = serializers.IntegerField()


class DataSerializer(serializers.Serializer):
    device = serializers.PrimaryKeyRelatedField(queryset=Device.objects.all())
    unit = serializers.PrimaryKeyRelatedField(queryset=DeviceUnit.objects.all())
    data = serializers.ListSerializer(child=serializers.CharField())


class TemperatureUnitValueSerializer(serializers.ModelSerializer):
    class Meta:
        model = TemperatureUnitValue
        fields = ('value', 'unit', 'timestamp')