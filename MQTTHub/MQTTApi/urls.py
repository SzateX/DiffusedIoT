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
    url(r'^dashboard/hub/(?P<hub>\d+)/device/(?P<pk>\d+)/permissions/$', v.DevicePermissionsView.as_view(), name='hub_device_permissions'),
    url(r'^dashboard/hub/(?P<hub>\d+)/device/(?P<pk>\d+)/permissions/add_user/$', v.AddDeviceUserPermissionView.as_view(), name='add_user_permission'),
    url(r'^dashboard/hub/(?P<hub>\d+)/device/(?P<pk>\d+)/permissions/add_group/$', v.AddDeviceGroupPermissionView.as_view(), name='add_group_permission'),
    url(r'^dashboard/hub/(?P<hub>\d+)/device/(?P<device>\d+)/permissions/user/(?P<pk>\d+)/$', v.UpdateDeviceUserPermissionView.as_view(), name='update_user_permission'),
    url(r'^dashboard/hub/(?P<hub>\d+)/device/(?P<device>\d+)/permissions/group/(?P<pk>\d+)/$', v.UpdateDeviceGroupPermissionView.as_view(), name='update_group_permission'),
] + api_urls.urlpatterns
