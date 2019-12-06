from django.conf.urls import url
import MQTTApi.views as v
import MQTTApi.api_urls as api_urls

urlpatterns = [
    url(r'^login/$', v.HubLoginView.as_view(), name='hub_login'),
    url(r'^logout/$', v.HubLogoutView.as_view(), name='hub_logout'),
    url(r'^dashboard/$', v.HubDashboard.as_view(), name='hub_dashboard'),
    url(r'^dashboard/hub/(?P<hub>\d+)/$', v.HubDeviceView.as_view(), name='hub_devices'),
    url(r'^dashboard/hub/(?P<hub>\d+)/add_device/$', v.AddDeviceView.as_view(), name='hub_devices_add'),
    url(r'^dashboard/hub/(?P<hub>\d+)/device/(?P<pk>\d+)/update/$', v.UpdateDeviceView.as_view(), name='hub_devices_update'),
    url(r'^dashboard/hub/(?P<hub>\d+)/device/(?P<pk>\d+)/permissions/$', v.DevicePermissionsView.as_view(), name='hub_device_permissions')
] + api_urls.urlpatterns
