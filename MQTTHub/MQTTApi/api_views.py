import requests
from django.http import Http404
from rest_framework.response import Response
from rest_framework.views import APIView

from MQTTHub.settings import AUTH_SERVICE_ADDRESS
from .models import Device
from .serializers import DeviceSerializer


class DevicesApiForUserView(APIView):
    def get_me(self):
        response = requests.get(
            AUTH_SERVICE_ADDRESS + "/api/get_me/",
            headers={
                'Authorization': "Bearer " + self.request.COOKIES.get('user_token')
            }
        )

        if response.status_code != 200:
            raise Exception("Error in connection with AuthService: "
                            + response.text)

        return response.json()

    def get_user_permissions(self, user_id):
        response = requests.get(
            AUTH_SERVICE_ADDRESS + "/api/hubs/%d/registred_devices/user_permissions/for_user/%d/" % (int(self.kwargs['hub']), user_id))

        if response.status_code != 200:
            raise Exception("Error in connection with AuthService: "
                            + response.text)

        return response.json()

    def get_group_permissions(self, group_ids):
        response = requests.get(
            AUTH_SERVICE_ADDRESS + "/api/hubs/%d/registred_devices/group_permissions/for_groups" % int(self.kwargs['hub']), json={"pk": group_ids})

        if response.status_code != 200:
            raise Exception("Error in connection with AuthService: "
                            + response.text)

        return response.json()

    def get_device_user_permission(self, device_id):
        response = requests.get(
            AUTH_SERVICE_ADDRESS + "/api/hubs/%d/registred_devices/%d/user_permissions/" % (int(self.kwargs['hub']), device_id))

        if response.status_code != 200:
            raise Exception("Error in connection with AuthService: "
                            + response.text)

        return response.json()

    def get_device_group_permission(self, device_id):
        response = requests.get(
            AUTH_SERVICE_ADDRESS + "/api/hubs/%d/registred_devices/%d/group_permissions/" % (
            int(self.kwargs['hub']), device_id))

        if response.status_code != 200:
            raise Exception("Error in connection with AuthService: "
                            + response.text)

        return response.json()

    def get(self, request, pk=None, format=None):
        if pk is None:
            return self.get_all(request, format)
        return self.get_one(request, pk, format)

    def get_all(self, request, format=None):
        me = self.get_me()
        if me['is_staff']:
            devices = Device.objects.all()
        else:
            user_permissions = self.get_user_permissions(me['pk'])
            group_permissions = self.get_group_permissions(list(map(lambda group: group['pk'], me['groups'])))
            devices_pk = set(
                map(lambda x: x['device'], group_permissions)).union(
                set(map(lambda x: x['device'], user_permissions)))
            devices = Device.objects.filter(pk__in=devices_pk)
        serializer = DeviceSerializer(devices, many=True)
        return Response(serializer.data)

    def get_one(self, request, pk, format=None):
        me = self.get_me()
        if not me['is_staff']:
            user_permissions = self.get_device_user_permission(pk)
            group_permissions = self.get_device_group_permission(pk)
            groups_pk = map(lambda group: group['pk'], me['groups'])
            filtered_group_permissions = filter(
                lambda x: x['pk'] in groups_pk and x['read_permission'] is True,
                group_permissions)
            filtered_user_permissions = filter(
                lambda x: x['pk'] == me['pk'] and x['read_permission'] is True,
                user_permissions)
            devices_pk = set(
                map(lambda x: x['device'], filtered_group_permissions)).union(
                set(map(lambda x: x['device'], filtered_user_permissions)))
            if pk not in devices_pk:
                raise Http404
        try:
            devices = Device.objects.get(pk=pk)
        except Device.DoesNotExist:
            raise Http404
        serializer = DeviceSerializer(devices)
        return Response(serializer.data)
