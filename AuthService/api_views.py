from django.http import Http404
from rest_framework import mixins, generics, status
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
        if pk is not None:
            obj = User.objects.all()
        else:
            obj = self.get_object(pk)
        serializer = UserSerializer(obj, many=pk is not None)
        return Response(serializer.data)


class GroupsView(APIView):
    def get_object(self, pk):
        try:
            user = Group.objects.get(pk=pk)
            return user
        except User.DoesNotExist:
            raise Http404

    def get(self, request, pk=None, format=None):
        if pk is not None:
            obj = Group.objects.all()
        else:
            obj = self.get_object(pk)
        serializer = GroupSerializer(obj, many=pk is not None)
        return Response(serializer.data)


