import json

import requests
from django.http import Http404
from django.utils import timezone
from rest_framework import status, permissions
from rest_framework.exceptions import PermissionDenied
from rest_framework.response import Response
from rest_framework.views import APIView

from MQTTApi.enums import UnitType
from MQTTApi.mqtt_parser import mqtt_incoming
from MQTTApi.services import AuthServiceApi
from MQTTHub.settings import AUTH_SERVICE_ADDRESS, HUB_ID
from drivers.GTS.driver import incoming_function
from .models import Device, DeviceUnit, ConnectedUnit, TemperatureUnitValue, \
    HumidityUnitValue, SwitchUnitValue
from .serializers import DeviceSerializer, DeviceUnitSerializer, \
    ConnectedUnitSerializer, ConnectedUnitSaveSerializer, DataSerializer, \
    TemperatureUnitValueSerializer, HumidityUnitValueSerializer, \
    SwitchUnitValueSerializer


class IsAuthorizedHub(permissions.BasePermission):
    def has_permission(self, request, view):
        key = request.META.get("HTTP_X_API_KEY")
        if key is None:
            raise PermissionDenied("Unauthorized Hub")
        hub_id = request.META.get("HTTP_HUB_ID")
        if hub_id is None:
            raise PermissionDenied("Unauthorized Hub")
        response = AuthServiceApi.verify_hub_api_key(hub_id, key)
        return response['is_valid']


class DevicesApiForUserView(APIView):
    permission_classes = [IsAuthorizedHub]

    def get(self, request, pk=None, format=None):
        if pk is None:
            return self.get_all(request, format)
        return self.get_one(request, pk, format)

    def post(self, request, format=None):
        me = AuthServiceApi.get_me(self.request.headers.get('Authorization'))
        if not me['is_staff']:
            return Response(status=status.HTTP_403_FORBIDDEN)
        serializer = DeviceSerializer(data=request.data)
        if serializer.is_valid():
            device = serializer.save()
            AuthServiceApi.register_device(HUB_ID, device)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, pk, format=None):
        me = AuthServiceApi.get_me(self.request.headers.get('Authorization'))
        if not me['is_staff']:
            return Response(status=status.HTTP_403_FORBIDDEN)
        try:
            device = Device.objects.get(pk=pk)
        except Device.DoesNotExist:
            raise Http404
        serializer = DeviceSerializer(device, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk, format=None):
        me = AuthServiceApi.get_me(self.request.headers.get('Authorization'))
        if not me['is_staff']:
            return Response(status=status.HTTP_403_FORBIDDEN)
        try:
            device = Device.objects.get(pk=pk)
        except Device.DoesNotExist:
            raise Http404
        AuthServiceApi.unregister_device(HUB_ID, device)
        device.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    def get_all(self, request, format=None):
        me = AuthServiceApi.get_me(request.headers.get('Authorization'))
        if me['is_staff']:
            devices = Device.objects.all()
        else:
            devices_pks = AuthServiceApi.get_registered_devices_with_read_perm(HUB_ID, me['pk'])['read_permission_devices']
            devices = Device.objects.filter(pk__in=devices_pks)
        serializer = DeviceSerializer(devices, many=True)
        return Response(serializer.data)

    def get_one(self, request, pk, format=None):
        me = AuthServiceApi.get_me(self.request.headers.get('Authorization'))
        if not me['is_staff']:
            read_permission = AuthServiceApi.has_read_permission(HUB_ID, pk, me['pk'])
            if not read_permission['has_read_perm']:
                raise Http404
        try:
            devices = Device.objects.get(pk=pk)
        except Device.DoesNotExist:
            raise Http404
        serializer = DeviceSerializer(devices)
        return Response(serializer.data)


class DeviceUnitsApiView(APIView):
    permission_classes = [IsAuthorizedHub]

    def get(self, request, device, pk=None, format=None):
        me = AuthServiceApi.get_me(self.request.headers.get('Authorization'))
        device_obj = Device.objects.get(pk=device)
        if pk is None:
            if me['is_staff']:
                objects = DeviceUnit.objects.filter(device=device_obj)
            else:
                read_permission = AuthServiceApi.has_read_permission(HUB_ID,
                                                                     device,
                                                                     me['pk'])
                if not read_permission['has_read_perm']:
                    return Response(status=status.HTTP_403_FORBIDDEN)
                objects = DeviceUnit.objects.filter(device=device_obj)
        else:
            read_permission = AuthServiceApi.has_read_permission(HUB_ID,
                                                                 device,
                                                                 me['pk'])
            if me['is_staff']:
                objects = DeviceUnit.objects.get(device=device_obj, pk=pk)
            else:
                if not read_permission['has_read_perm']:
                    return Response(status=status.HTTP_403_FORBIDDEN)
                objects = DeviceUnit.objects.get(device=device_obj, pk=pk)

        serializer = DeviceUnitSerializer(objects, many=pk is None)
        return Response(serializer.data)

    def post(self, request, device, format=None):
        me = AuthServiceApi.get_me(self.request.headers.get('Authorization'))
        if not me['is_staff']:
            return Response(status=status.HTTP_403_FORBIDDEN)
        serializer = DeviceUnitSerializer(data=request.data)
        if serializer.is_valid():
            device = Device.objects.get(pk=device)
            DeviceUnit.objects.create(device=device,
                                      **serializer.validated_data)
            return Response(serializer.validated_data,
                            status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, device, pk, format=None):
        me = AuthServiceApi.get_me(self.request.headers.get('Authorization'))
        if not me['is_staff']:
            return Response(status=status.HTTP_403_FORBIDDEN)
        serializer = DeviceUnitSerializer(data=request.data)
        if serializer.is_valid():
            unit = DeviceUnit.objects.get(pk=pk)
            unit.name = serializer.validated_data['name']
            unit.direction = serializer.validated_data['direction']
            unit.type_of_unit = serializer.validated_data['type_of_unit']
            unit.save()
            return Response(serializer.validated_data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, device, pk, format=None):
        me = AuthServiceApi.get_me(self.request.headers.get('Authorization'))
        if not me['is_staff']:
            return Response(status=status.HTTP_403_FORBIDDEN)
        unit = DeviceUnit.objects.get(pk=pk)
        unit.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class ConnectedUnitApiView(APIView):
    permission_classes = [IsAuthorizedHub]

    def get(self, request, from_unit, pk=None, format=None):
        me = AuthServiceApi.get_me(self.request.headers.get('Authorization'))
        if not me['is_staff']:
            return Response(status=status.HTTP_403_FORBIDDEN)
        if pk is None:
            return self.get_many(request, from_unit, format)
        else:
            return self.get_single(request, from_unit, pk, format)

    def get_single(self, request, from_unit, pk, format=None):
        f_unit = DeviceUnit.objects.get(pk=from_unit)
        connected_unit = ConnectedUnit.objects.get(from_unit=f_unit, pk=pk)
        serializer = ConnectedUnitSerializer(connected_unit)
        return Response(serializer.data)

    def get_many(self, request, from_unit, format=None):
        f_unit = DeviceUnit.objects.get(pk=from_unit)
        connected_units = ConnectedUnit.objects.filter(from_unit=f_unit)
        serializer = ConnectedUnitSerializer(connected_units, many=True)
        return Response(serializer.data)

    def post(self, request, format=None):
        me = AuthServiceApi.get_me(self.request.headers.get('Authorization'))
        if not me['is_staff']:
            return Response(status=status.HTTP_403_FORBIDDEN)
        serializer = ConnectedUnitSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()

            return Response(request.data,
                            status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk, format=None):
        me = AuthServiceApi.get_me(self.request.headers.get('Authorization'))
        if not me['is_staff']:
            return Response(status=status.HTTP_403_FORBIDDEN)
        connected_unit = ConnectedUnit.objects.get(pk=pk)
        connected_unit.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class IncomingDataToUnitApiView(APIView):
    permission_classes = [IsAuthorizedHub]

    def post(self, request, format=None):
        serializer = DataSerializer(data=request.data)
        try:
            if serializer.is_valid():
                device = serializer.validated_data['device']
                unit = serializer.validated_data['unit']
                data = serializer.validated_data['data']
                objs = []
                for data_obj in data:
                    try:
                        d = json.loads(data_obj)
                    except Exception as e:
                        pass
                    if 'data' not in d or 'type' not in d:
                        return Response({'error': 'Invalid data'}, status=status.HTTP_400_BAD_REQUEST)
                    t = d['type']
                    d = json.loads(d['data'])
                    if t == 'TemperatureUnitValue':
                        serializer = TemperatureUnitValueSerializer(data=d)
                        if serializer.is_valid():
                            obj = TemperatureUnitValue(device_unit=unit, incoming=True, **serializer.validated_data)
                            objs.append(obj)
                        else:
                            return Response(serializer.errors,
                                            status=status.HTTP_400_BAD_REQUEST)
                    else:
                        return Response({'error': 'Invalid type'},
                                        status=status.HTTP_400_BAD_REQUEST)
                mqtt_incoming(device, unit, objs)
                return Response(request.data,
                                status=status.HTTP_200_OK)
        except Exception as e:
            pass
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class GetDataFromUnitView(APIView):
    permission_classes = [IsAuthorizedHub]

    def get(self, request, device, pk, format=None):
        me = AuthServiceApi.get_me(self.request.headers.get('Authorization'))
        if not me['is_staff']:
            read_permission = AuthServiceApi.has_read_permission(HUB_ID,
                                                                 device,
                                                                 me['pk'])
            if not read_permission['has_read_perm']:
                return Response(status=status.HTTP_403_FORBIDDEN)

        try:
            device_obj = Device.objects.get(pk=device)
            unit = DeviceUnit.objects.get(device=device_obj, pk=pk)
        except Device.DoesNotExist:
            raise Http404
        except DeviceUnit.DoesNotExist:
            raise Http404

        if unit.type_of_unit == UnitType.HUMIDITY_UNIT:
            objs = HumidityUnitValue.objects.filter(device_unit=unit).order_by('-timestamp')[:50]
            serializer = HumidityUnitValueSerializer(objs, many=True)
        elif unit.type_of_unit == UnitType.TEMPERATURE_UNIT:
            objs = TemperatureUnitValue.objects.filter(device_unit=unit).order_by('-timestamp')[:50]
            serializer = TemperatureUnitValueSerializer(objs, many=True)
        elif unit.type_of_unit == UnitType.SWITCH_UNIT:
            objs = SwitchUnitValue.objects.filter(device_unit=unit).order_by('-timestamp')[:50]
            serializer = SwitchUnitValueSerializer(objs, many=True)
        else:
            raise Exception("Bad Unit Type")

        return Response(serializer.data, status=status.HTTP_200_OK)