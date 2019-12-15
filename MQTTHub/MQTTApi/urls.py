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
    url(r'^dashboard/hub/(?P<hub>\d+)/device/(?P<device>\d+)/permissions/user/(?P<pk>\d+)/update/$', v.UpdateDeviceUserPermissionView.as_view(), name='update_user_permission'),
    url(r'^dashboard/hub/(?P<hub>\d+)/device/(?P<device>\d+)/permissions/group/(?P<pk>\d+)/update/$', v.UpdateDeviceGroupPermissionView.as_view(), name='update_group_permission'),
    url(r'^dashboard/hub/(?P<hub>\d+)/device/(?P<device>\d+)/permissions/user/(?P<pk>\d+)/delete/$', v.DeleteDeviceUserPermissionView.as_view(), name='delete_user_permission'),
    url(r'^dashboard/hub/(?P<hub>\d+)/device/(?P<device>\d+)/permissions/group/(?P<pk>\d+)/delete/$', v.DeleteDeviceGroupPermissionView.as_view(), name='delete_group_permission'),
    url(r'^dashboard/hub/(?P<hub>\d+)/device/(?P<pk>\d+)/units/$', v.DeviceUnitsView.as_view(), name='device_units'),
    url(r'^dashboard/hub/(?P<hub>\d+)/device/(?P<pk>\d+)/units/add/$', v.AddDeviceUnitView.as_view(), name='add_device_unit'),
    url(r'^dashboard/hub/(?P<hub>\d+)/device/(?P<device>\d+)/units/(?P<pk>\d+)/update/$', v.UpdateDeviceUnitView.as_view(), name='update_device_unit'),
    url(r'^dashboard/hub/(?P<hub>\d+)/device/(?P<device>\d+)/units/(?P<pk>\d+)/delete/$', v.DeleteDeviceUnitView.as_view(), name='delete_device_unit'),
    url(r'^dashboard/hub/(?P<hub>\d+)/device/(?P<device>\d+)/units/(?P<pk>\d+)/connect_unit/$', v.ConnectUnitHubSelectView.as_view(), name='connect_unit_hub_select'),
    url(r'^dashboard/hub/(?P<hub>\d+)/device/(?P<device>\d+)/units/(?P<pk>\d+)/connect_unit/(?P<dest_hub>\d+)/$', v.ConnectUnitDeviceSelectView.as_view(), name='connect_unit_device_select'),
    url(r'^dashboard/hub/(?P<hub>\d+)/device/(?P<device>\d+)/units/(?P<pk>\d+)/connect_unit/(?P<dest_hub>\d+)/(?P<dest_device>\d+)/$', v.ConnectUnitSelectUnitView.as_view(), name='connect_unit_unit_select'),
    url(r'^dashboard/hub/(?P<hub>\d+)/device/(?P<device>\d+)/units/(?P<pk>\d+)/connect_unit/(?P<dest_hub>\d+)/(?P<dest_device>\d+)/(?P<dest_unit>\d+)/$', v.ConnectUnitConfirmView.as_view(), name='connect_unit_confirm'),
    url(r'^dashboard/hub/(?P<hub>\d+)/device/(?P<device>\d+)/units/(?P<pk>\d+)/connected_units/$', v.ConnectedUnitList.as_view(), name='connected_unit_lists'),
] + api_urls.urlpatterns
