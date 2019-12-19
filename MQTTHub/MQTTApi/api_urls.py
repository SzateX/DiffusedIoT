from django.conf.urls import url
import MQTTApi.api_views as v

urlpatterns = [
    url(r'^internal_api/devices_for_user/$', v.DevicesApiForUserView.as_view(), name='devices_for_user'),
    url(r'^internal_api/devices_for_user/(?P<pk>\d+)/$', v.DevicesApiForUserView.as_view(), name='device_for_user'),
    url(r'^internal_api/devices_for_user/(?P<device>\d+)/units/$', v.DeviceUnitsApiView.as_view(), name='devices_units'),
    url(r'^internal_api/devices_for_user/(?P<device>\d+)/units/(?P<pk>\d+)/$', v.DeviceUnitsApiView.as_view(), name='devices_unit_detail'),
    url(r'^internal_api/connected_units/from_unit/(?P<from_unit>\d+)/$', v.ConnectedUnitApiView.as_view(), name='get_connected_units_with_unit'),
    url(r'^internal_api/connected_units/from_unit/(?P<from_unit>\d+)/(?P<pk>\d+)/$', v.ConnectedUnitApiView.as_view(), name='get_connected_unit_with_unit'),
    url(r'^internal_api/connected_units/$', v.ConnectedUnitApiView.as_view(), name='connected_units'),
    url(r'^internal_api/connected_units/(?P<pk>\d+)/$', v.ConnectedUnitApiView.as_view(), name='connected_unit'),
    url(r'^internal_api/connected_units/send_data/$', v.IncomingDataToUnitApiView.as_view(), name='data_to_unit'),
]