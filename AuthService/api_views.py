from django.http import Http404
from rest_framework import mixins, generics, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .serializers import *
from .models import *
from rest_framework.views import APIView

from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView, TokenVerifyView


class APIUserLoginView(TokenObtainPairView):
    pass


class APIRefreshUserToken(TokenRefreshView):
    pass


class APIVerifyUserToken(TokenVerifyView):
    pass


class HubListView(mixins.ListModelMixin, generics.GenericAPIView):
    queryset = Hub.objects.all()
    serializer_class = HubSerializer

    def get(self, request, *args, **kwargs):
        return self.list(request, *args, **kwargs)


class HubValidApiKeyView(APIView):
    def get_object(self, pk):
        try:
            hub = Hub.objects.get(pk=pk)
            api_keys = HubAPIKey.objects.order_by('-pk').filter(organization=hub, revoked=False)
            if not api_keys:
                raise Http404
            return api_keys[0]
        except Hub.DoesNotExist:
            raise Http404

    def get(self, request, pk, format=None):
        api_key = self.get_object(pk)
        print(request.data)
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
    def post(self, request, format=None):
        serializer = RegisterDeviceSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UsersView(APIView):
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
    def get_object(self, model, **kwargs):
        try:
            return model.objects.get(**kwargs)
        except model.DoesNotExist:
            raise Http404

    def get(self, request, pk=None, format=None):
        hub = self.get_object(Hub, pk=self.kwargs.get("hub"))
        device = self.get_object(RegisteredDevice, hub=hub, pk=self.kwargs.get("device"))
        if pk is None:
            obj = UserDevicePermission.objects.filter(device=device)
        else:
            obj = self.get_object(UserDevicePermission, device=device, pk=pk)
        serializer = UserDevicePermissionSerializer(obj, many=pk is None)
        return Response(serializer.data)

    def post(self, request, format=None):
        hub = self.get_object(Hub, pk=self.kwargs.get("hub"))
        device = self.get_object(RegisteredDevice, hub=hub, pk=self.kwargs.get("device"))
        serializer = UserDevicePermissionSerializer(request.data)
        if serializer.is_valid():
            if device.pk != serializer.data.get("device"):
                return Response(serializer.errors,
                                status=status.HTTP_400_BAD_REQUEST)
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, pk, format=None):
        hub = self.get_object(Hub, pk=self.kwargs.get("hub"))
        device = self.get_object(RegisteredDevice, hub=hub, pk=self.kwargs.get("device"))
        obj = self.get_object(UserDevicePermission, device=device, pk=pk)
        serializer = UserDevicePermissionSerializer(obj, request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk, format=None):
        hub = self.get_object(Hub, pk=self.kwargs.get("hub"))
        device = self.get_object(RegisteredDevice, hub=hub,
                                 pk=self.kwargs.get("device"))
        obj = self.get_object(UserDevicePermission, device=device, pk=pk)
        obj.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class DeviceGroupPermissionsView(APIView):
    def get_object(self, model, **kwargs):
        try:
            return model.objects.get(**kwargs)
        except model.DoesNotExist:
            raise Http404

    def get(self, request, pk=None, format=None):
        hub = self.get_object(Hub, pk=self.kwargs.get("hub"))
        device = self.get_object(RegisteredDevice, hub=hub, pk=self.kwargs.get("device"))
        if pk is None:
            obj = GroupDevicePermission.objects.filter(device=device)
        else:
            obj = self.get_object(GroupDevicePermission, device=device, pk=pk)
        serializer = GroupDevicePermissionSerializer(obj, many=pk is None)
        return Response(serializer.data)

    def post(self, request, format=None):
        hub = self.get_object(Hub, pk=self.kwargs.get("hub"))
        device = self.get_object(RegisteredDevice, hub=hub, pk=self.kwargs.get("device"))
        serializer = GroupDevicePermissionSerializer(request.data)
        if serializer.is_valid():
            if device.pk != serializer.data.get("device"):
                return Response(serializer.errors,
                                status=status.HTTP_400_BAD_REQUEST)
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, pk, format=None):
        hub = self.get_object(Hub, pk=self.kwargs.get("hub"))
        device = self.get_object(RegisteredDevice, hub=hub, pk=self.kwargs.get("device"))
        obj = self.get_object(GroupDevicePermission, device=device, pk=pk)
        serializer = GroupDevicePermissionSerializer(obj, request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk, format=None):
        hub = self.get_object(Hub, pk=self.kwargs.get("hub"))
        device = self.get_object(RegisteredDevice, hub=hub, pk=self.kwargs.get("device"))
        obj = self.get_object(GroupDevicePermission, device=device, pk=pk)
        obj.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class DeviceUserPermissionListView(APIView):
    def get_object(self, model, **kwargs):
        try:
            return model.objects.get(**kwargs)
        except model.DoesNotExist:
            raise Http404

    def get(self, request, hub, user=None, format=None):
        hub = self.get_object(Hub, pk=self.kwargs.get("hub"))
        devices = RegisteredDevice.objects.filter(hub=hub)
        if user != None:
            user_permission = UserDevicePermission.objects.filter(device__in=devices, user_pk=user)
        else:
            user_permission = UserDevicePermission.objects.filter(device__in=devices)
        serializer = UserDevicePermissionSerializer(user_permission, many=True)
        return Response(serializer.data)


class DeviceGroupPermissionListView(APIView):
    def get_object(self, model, **kwargs):
        try:
            return model.objects.get(**kwargs)
        except model.DoesNotExist:
            raise Http404

    def get(self, request, hub, format=None):
        hub = self.get_object(Hub, pk=self.kwargs.get("hub"))
        devices = RegisteredDevice.objects.filter(hub=hub)
        if request.data is not None and len(request.data):
            serializer = GroupPksSerializer(request.data, many=True)
            if serializer.is_valid():
                group_permission = GroupDevicePermission.objects.filter(device__in=devices, group_pk__in=serializer.data)
        else:
            group_permission = GroupDevicePermission.objects.filter(device__in=devices)
        serializer = GroupDevicePermissionSerializer(group_permission, many=True)
        return Response(serializer.data)


class GetMe(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        return Response(MeSerializer(self.request.user).data)