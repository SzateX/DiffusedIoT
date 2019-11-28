from rest_framework.views import APIView


class DevicesApiView(APIView):
    def get(self, request, pk=None, format=None):
        if pk is None:
            return self.get_all(request, format)
        return self.get_one(request, pk, format)

    def get_all(self, request, format=None):


    def get_one(self, request, pk, format=None):
        pass
