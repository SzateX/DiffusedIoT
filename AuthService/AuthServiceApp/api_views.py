import typing

from django.http import Http404, HttpRequest
from django.shortcuts import get_object_or_404
from rest_framework import mixins, generics, status
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework_api_key.permissions import BaseHasAPIKey

from AuthServiceApp.serializers import *
from AuthServiceApp.models import *
from rest_framework.views import APIView

from rest_framework_simplejwt.views import TokenObtainPairView, \
    TokenRefreshView, TokenVerifyView

from django.db.models import Q


class HasHubAPIKey(BaseHasAPIKey):
    model = HubAPIKey

    def has_permission(self, request: HttpRequest, view: typing.Any) -> bool:
        assert self.model is not None, (
                "%s must define `.model` with the API key model to use"
                % self.__class__.__name__
        )
        key = self.get_key(request)
        if not key:
            return False
        hub_id = request.META.get("HTTP_HUB_ID")
        try:
            hub = Hub.objects.get(pk=int(hub_id))
        except Hub.DoesNotExist:
            raise PermissionDenied("Unauthorized Hub")
        api_keys = HubAPIKey.objects.order_by('-pk').filter(
            hub=hub, revoked=False)
        if not api_keys:
            raise PermissionDenied("Unauthorized Hub")
        for api_key in api_keys:
            if api_key.is_valid(key):
                return True
        return False


class APIUserLoginView(TokenObtainPairView):
    permission_classes = [HasHubAPIKey]


class APIRefreshUserToken(TokenRefreshView):
    permission_classes = [HasHubAPIKey]


class APIVerifyUserToken(TokenVerifyView):
    permission_classes = [HasHubAPIKey]


class HubView(mixins.RetrieveModelMixin, generics.GenericAPIView):
    queryset = Hub.objects.all()
    serializer_class = HubSerializer
    permission_classes = [HasHubAPIKey]

    def get(self, request, *args, **kwargs):
        return self.retrieve(request, *args, **kwargs)


class HubListView(mixins.ListModelMixin, generics.GenericAPIView):
    queryset = Hub.objects.all()
    serializer_class = HubSerializer
    permission_classes = [HasHubAPIKey]

    def get(self, request, *args, **kwargs):
        return self.list(request, *args, **kwargs)


class HubValidApiKeyView(APIView):
    permission_classes = [HasHubAPIKey]

    def get_object(self, pk):
        try:
            hub = Hub.objects.get(pk=pk)
            api_keys = HubAPIKey.objects.order_by('-pk').filter(
                hub=hub, revoked=False)
            if not api_keys:
                raise Http404
            return api_keys[0]
        except Hub.DoesNotExist:
            raise Http404

    def get(self, request, pk, format=None):
        api_key = self.get_object(pk)
        serializer = HubApiKeySerializer(data=request.data)
        if serializer.is_valid():
            data = {
                "is_valid": api_key.is_valid(serializer.data['api_key']),
                "hub_id": pk,
                "api_key": serializer.data['api_key']
            }
            return Response(HubApiKeyValidateSerialzier(data).data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class RegisterDeviceAPIView(APIView):
    permission_classes = [HasHubAPIKey]

    def post(self, request, format=None):
        serializer = RegisterDeviceSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UnregisterDeviceAPIView(APIView):
    permission_classes = [HasHubAPIKey]

    def delete(self, request, format=None):
        serializer = RegisterDeviceSerializer(data=request.data)
        if serializer.is_valid():
            try:
                device = RegisteredDevice.objects.get(
                    hub=serializer.validated_data['hub'],
                    device_id=serializer.validated_data['device_id']
                )
                device.delete()
                return Response(status=status.HTTP_204_NO_CONTENT)
            except RegisteredDevice.DoesNotExist:
                raise Http404
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UsersView(APIView):
    permission_classes = [HasHubAPIKey]

    def get_object(self, pk):
        try:
            user = User.objects.get(pk=pk)
            return user
        except User.DoesNotExist:
            raise Http404

    def get(self, request, pk=None, format=None):
        if pk is None:
            obj = User.objects.all()
        else:
            obj = self.get_object(pk)
        serializer = UserSerializer(obj, many=pk is None)
        return Response(serializer.data)


class GroupsView(APIView):
    permission_classes = [HasHubAPIKey]

    def get_object(self, pk):
        try:
            user = Group.objects.get(pk=pk)
            return user
        except User.DoesNotExist:
            raise Http404

    def get(self, request, pk=None, format=None):
        if pk is None:
            obj = Group.objects.all()
        else:
            obj = self.get_object(pk)
        serializer = GroupSerializer(obj, many=pk is None)
        return Response(serializer.data)


class DeviceUserPermissionsView(APIView):
    permission_classes = [HasHubAPIKey]

    def get_object(self, model, **kwargs):
        try:
            return model.objects.get(**kwargs)
        except model.DoesNotExist:
            raise Http404

    def get(self, request, hub, device, pk=None, format=None):
        hub = self.get_object(Hub, pk=self.kwargs.get("hub"))
        device = self.get_object(RegisteredDevice, hub=hub,
                                 device_id=self.kwargs.get("device"))
        if pk is None:
            obj = UserDevicePermission.objects.filter(device=device)
        else:
            obj = self.get_object(UserDevicePermission, device=device, pk=pk)
        serializer = UserDevicePermissionSerializer(obj, many=pk is None)
        return Response(serializer.data)

    def post(self, request, hub, device, format=None):
        hub = self.get_object(Hub, pk=self.kwargs.get("hub"))
        device = self.get_object(RegisteredDevice, hub=hub,
                                 device_id=self.kwargs.get("device"))
        serializer = UserDevicePermissionSerializer(data=request.data, hub=hub)
        if serializer.is_valid():
            if device.pk != serializer.validated_data.get("device").pk:
                return Response(serializer.errors,
                                status=status.HTTP_400_BAD_REQUEST)
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, hub, device, pk, format=None):
        hub = self.get_object(Hub, pk=self.kwargs.get("hub"))
        device = self.get_object(RegisteredDevice, hub=hub,
                                 device_id=self.kwargs.get("device"))
        obj = self.get_object(UserDevicePermission, device=device, pk=pk)
        serializer = UserDevicePermissionSerializer(obj, request.data, hub=hub)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, hub, device, pk, format=None):
        hub = self.get_object(Hub, pk=self.kwargs.get("hub"))
        device = self.get_object(RegisteredDevice, hub=hub,
                                 device_id=self.kwargs.get("device"))
        obj = self.get_object(UserDevicePermission, device=device, pk=pk)
        obj.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class DeviceGroupPermissionsView(APIView):
    permission_classes = [HasHubAPIKey]

    def get_object(self, model, **kwargs):
        try:
            return model.objects.get(**kwargs)
        except model.DoesNotExist:
            raise Http404

    def get(self, request, hub, device, pk=None, format=None):
        hub = self.get_object(Hub, pk=self.kwargs.get("hub"))
        device = self.get_object(RegisteredDevice, hub=hub,
                                 device_id=self.kwargs.get("device"))
        if pk is None:
            obj = GroupDevicePermission.objects.filter(device=device)
        else:
            obj = self.get_object(GroupDevicePermission, device=device, pk=pk)
        serializer = GroupDevicePermissionSerializer(obj, many=pk is None)
        return Response(serializer.data)

    def post(self, request, hub, device, format=None):
        hub = self.get_object(Hub, pk=self.kwargs.get("hub"))
        device = self.get_object(RegisteredDevice, hub=hub,
                                 device_id=self.kwargs.get("device"))
        serializer = GroupDevicePermissionSerializer(data=request.data, hub=hub)
        if serializer.is_valid():
            if device.pk != serializer.validated_data.get("device").pk:
                return Response(serializer.errors,
                                status=status.HTTP_400_BAD_REQUEST)
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, hub, device, pk, format=None):
        hub = self.get_object(Hub, pk=self.kwargs.get("hub"))
        device = self.get_object(RegisteredDevice, hub=hub,
                                 device_id=self.kwargs.get("device"))
        obj = self.get_object(GroupDevicePermission, device=device, pk=pk)
        serializer = GroupDevicePermissionSerializer(obj, request.data, hub=hub)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, hub, device, pk, format=None):
        hub = self.get_object(Hub, pk=self.kwargs.get("hub"))
        device = self.get_object(RegisteredDevice, hub=hub,
                                 device_id=self.kwargs.get("device"))
        obj = self.get_object(GroupDevicePermission, device=device, pk=pk)
        obj.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class DeviceUserPermissionListView(APIView):
    permission_classes = [HasHubAPIKey]

    def get_object(self, model, **kwargs):
        try:
            return model.objects.get(**kwargs)
        except model.DoesNotExist:
            raise Http404

    def get(self, request, hub, user=None, format=None):
        hub = self.get_object(Hub, pk=self.kwargs.get("hub"))
        devices = RegisteredDevice.objects.filter(hub=hub)
        if user != None:
            user_permission = UserDevicePermission.objects.filter(
                device_id__in=devices, user_id=user)
        else:
            user_permission = UserDevicePermission.objects.filter(
                device_id__in=devices)
        serializer = UserDevicePermissionSerializer(user_permission, many=True)
        return Response(serializer.data)


class DeviceGroupPermissionListView(APIView):
    permission_classes = [HasHubAPIKey]

    def get_object(self, model, **kwargs):
        try:
            return model.objects.get(**kwargs)
        except model.DoesNotExist:
            raise Http404

    def get(self, request, hub, format=None):
        hub = self.get_object(Hub, pk=self.kwargs.get("hub"))
        devices = RegisteredDevice.objects.filter(hub=hub)
        print(request.data)
        if request.data is not None and len(request.data):
            serializer = GroupPksSerializer(data=request.data, many=True)
            if serializer.is_valid():
                group_permission = GroupDevicePermission.objects.filter(
                    device_id__in=devices, group_pk__in=serializer.data)
            else:
                return Response(serializer.errors,
                                status=status.HTTP_400_BAD_REQUEST)
        else:
            group_permission = GroupDevicePermission.objects.filter(
                device_id__in=devices)
        serializer = GroupDevicePermissionSerializer(group_permission,
                                                     many=True)
        return Response(serializer.data)


class HasReadPermissionForDevice(APIView):
    permission_classes = [HasHubAPIKey]

    def get_object(self, model, **kwargs):
        try:
            return model.objects.get(**kwargs)
        except model.DoesNotExist:
            raise Http404

    def get(self, request, hub, device, user, format=None):
        hub_obj = self.get_object(Hub, pk=hub)
        user = self.get_object(User, pk=user)
        if user.is_staff:
            return Response({'has_read_perm': True}, status=status.HTTP_200_OK)
        devices = RegisteredDevice.objects.filter(
            Q(device_user_perms__user=user, device_user_perms__read_permission=True) | Q(device_group_perms__group__in=user.groups.all(), device_group_perms__read_permission=True),
                                                  hub=hub_obj, device_id=device)
        if devices:
            return Response({'has_read_perm': True}, status=status.HTTP_200_OK)
        return Response({'has_read_perm': False}, status=status.HTTP_200_OK)


class HasWritePermissionForDevice(APIView):
    permission_classes = [HasHubAPIKey]

    def get_object(self, model, **kwargs):
        try:
            return model.objects.get(**kwargs)
        except model.DoesNotExist:
            raise Http404

    def get(self, request, hub, device, user, format=None):
        hub_obj = self.get_object(Hub, pk=hub)
        user = self.get_object(User, pk=user)
        if user.is_staff:
            return Response({'has_write_perm': True}, status=status.HTTP_200_OK)
        devices = RegisteredDevice.objects.filter(
            Q(device_user_perms__user=user, device_user_perms__write_permission=True) | Q(device_group_perms__group__in=user.groups.all(), device_group_perms__write_permission=True),
                                                  hub=hub_obj, device_id=device)
        if devices:
            return Response({'has_write_perm': True}, status=status.HTTP_200_OK)
        return Response({'has_write_perm': False}, status=status.HTTP_200_OK)


class RegistredDevicesWithReadPermission(APIView):
    permission_classes = [HasHubAPIKey]

    def get_object(self, model, **kwargs):
        try:
            return model.objects.get(**kwargs)
        except model.DoesNotExist:
            raise Http404

    def get(self, request, hub, user, format=None):
        hub_obj = self.get_object(Hub, pk=hub)
        user = self.get_object(User, pk=user)
        if user.is_staff:
            devices = RegisteredDevice.objects.all()
        else:
            devices = RegisteredDevice.objects.filter(
                Q(device_user_perms__user=user,
                    device_user_perms__read_permission=True) | Q(
                    device_group_perms__group__in=user.groups.all(),
                    device_group_perms__read_permission=True),
                hub=hub_obj)

        device_ids = list(map(lambda x: x.device_id, devices))
        return Response({'read_permission_devices': device_ids}, status=status.HTTP_200_OK)


class GetMe(APIView):
    permission_classes = [IsAuthenticated & HasHubAPIKey]

    def get(self, request, format=None):
        return Response(MeSerializer(self.request.user).data)
