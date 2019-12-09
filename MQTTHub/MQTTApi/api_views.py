import requests
from django.http import Http404
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from MQTTApi.services import AuthServiceApi
from MQTTHub.settings import AUTH_SERVICE_ADDRESS, HUB_ID
from .models import Device, DeviceUnit
from .serializers import DeviceSerializer, DeviceUnitSerializer


def get_devices_pks(self, me, user_permissions, group_permissions):
    groups_pk = map(lambda group: group['pk'], me['groups'])
    filtered_group_permissions = filter(
        lambda x: x['pk'] in groups_pk and x[
            'read_permission'] is True,
        group_permissions)
    filtered_user_permissions = filter(
        lambda x: x['pk'] == me['pk'] and x['read_permission'] is True,
        user_permissions)
    devices_pk = set(
        map(lambda x: x['device'], filtered_group_permissions)).union(
        set(map(lambda x: x['device'], filtered_user_permissions)))
    return devices_pk


class DevicesApiForUserView(APIView):
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

    def get_all(self, request, format=None):
        me = AuthServiceApi.get_me(request.headers.get('Authorization'))
        if me['is_staff']:
            devices = Device.objects.all()
        else:
            user_permissions = AuthServiceApi.get_user_permissions(HUB_ID,
                                                                   me['pk'])
            group_permissions = AuthServiceApi.get_group_permissions(HUB_ID,
                                                                     list(map(
                                                                         lambda
                                                                             group:
                                                                         group[
                                                                             'pk'],
                                                                         me[
                                                                             'groups'])))
            devices_pk = set(
                map(lambda x: x['device'], group_permissions)).union(
                set(map(lambda x: x['device'], user_permissions)))
            devices = Device.objects.filter(pk__in=devices_pk)
        serializer = DeviceSerializer(devices, many=True)
        return Response(serializer.data)

    def get_one(self, request, pk, format=None):
        me = AuthServiceApi.get_me(self.request.headers.get('Authorization'))
        if not me['is_staff']:
            user_permissions = AuthServiceApi.get_device_user_permissions(
                HUB_ID, pk)
            group_permissions = AuthServiceApi.get_device_group_permissions(
                HUB_ID, pk)
            devices_pk = get_devices_pks(me, user_permissions,
                                         group_permissions)
            if pk not in devices_pk:
                raise Http404
        try:
            devices = Device.objects.get(pk=pk)
        except Device.DoesNotExist:
            raise Http404
        serializer = DeviceSerializer(devices)
        return Response(serializer.data)


class DeviceUnitsApiView(APIView):
    def get(self, request, device, format=None):
        me = AuthServiceApi.get_me(self.request.headers.get('Authorization'))
        user_permissions = AuthServiceApi.get_device_user_permissions(HUB_ID,
                                                                      device)
        group_permissions = AuthServiceApi.get_device_group_permissions(HUB_ID,
                                                                        device)
        device_obj = Device.objects.get(pk=device)
        if me['is_staff']:
            objects = DeviceUnit.objects.filter(device=device_obj)
        else:
            devices_pk = get_devices_pks(me, user_permissions,
                                         group_permissions)
            if device not in devices_pk:
                return Response(status=status.HTTP_403_FORBIDDEN)
            objects = DeviceUnit.objects.filter(device=device_obj)

        serializer = DeviceUnitSerializer(objects, many=True)
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
                            status=status.HTTP_202_ACCEPTED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
