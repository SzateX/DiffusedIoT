from django.conf.urls import url
import MQTTHub.MQTTApi.api_views as v

urlpatterns = [
    url(r'^internal_api/devices_for_user/$', v.DevicesApiForUserView.as_view(), name='devices_for_user'),
    url(r'^internal_api/devices_for_user/(?P<pk>\d+)/$', v.DevicesApiForUserView.as_view(), name='device_for_user')
]