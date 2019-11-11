from django.http import Http404
from rest_framework import mixins, generics, status
from rest_framework.response import Response

from .serializers import *
from .models import *
from rest_framework.views import APIView


class HubListView(mixins.ListModelMixin, generics.GenericAPIView):
    queryset = Hub.objects.all()
    serializer_class = HubSerializer

    def get(self, request, *args, **kwargs):
        # print(HubAPIKey.objects.filter(organization=3))
        # print(dir(HubAPIKey.objects.get(organization=3, revoked=False)))
        # print(HubAPIKey.objects.get(organization=4, revoked=False).is_valid("6CTZS7Nz.VY3InnCDpMF8q2Mt4qd5AYKYOWZ0Y1KX"))
        # print(HubAPIKey.objects.get(organization=4, revoked=False).is_valid("zK7eaK8j.5GmCUoCtCtOJc6WP7GH94cVzBb8pGYzU"))
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
