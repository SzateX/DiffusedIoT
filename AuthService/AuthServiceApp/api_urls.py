from django.conf.urls import url
import AuthServiceApp.api_views as v

api_url_patterns = [
    url(r'^api/user_auth/sign_in/$', v.APIUserLoginView.as_view(),
        name='api_user_sign_in'),
    url(r'^api/user_auth/refresh_token/$', v.APIRefreshUserToken.as_view(),
        name='api_user_refresh_token'),
    url(r'^api/user_auth/verify_token/$', v.APIVerifyUserToken.as_view(),
        name='api_user_verify_token'),
    url(r'^api/hubs/$', v.HubListView.as_view(), name='api_hubs'),
    url(r'^api/hub/(?P<pk>\d+)/$', v.HubView.as_view(), name='api_hub_detail'),
    url(r'^api/hubs/validate_api_key/(?P<pk>\d+)/$',
        v.HubValidApiKeyView.as_view(), name='api_key_validate'),
    url(r'^api/hubs/register_device/$', v.RegisterDeviceAPIView.as_view(),
        name='api_register_device'),
    url(r'^api/hubs/unregister_device/$', v.UnregisterDeviceAPIView.as_view(),
        name='api_unregister_device'),
    url(r'^api/users/$', v.UsersView.as_view(), name='api_users'),
    url(r'^api/users/(?P<pk>\d+)/$', v.UsersView.as_view(),
        name='api_users_detail'),
    url(r'^api/groups/$', v.GroupsView.as_view(), name='api_groups'),
    url(r'^api/groups/(?P<pk>\d+)/$', v.GroupsView.as_view(),
        name='api_groups_detail'),
    url(
        r'^api/hubs/(?P<hub>\d+)/registred_devices/'
        r'(?P<device>\d+)/user_permissions/$',
        v.DeviceUserPermissionsView.as_view(),
        name="api_device_user_permissions"),
    url(
        r'^api/hubs/(?P<hub>\d+)/registred_devices/'
        r'(?P<device>\d+)/user_permissions/(?P<pk>\d+)/$',
        v.DeviceUserPermissionsView.as_view(),
        name="api_device_user_permissions_detail"),
    url(
        r'^api/hubs/(?P<hub>\d+)/registred_devices/'
        r'(?P<device>\d+)/group_permissions/$',
        v.DeviceGroupPermissionsView.as_view(),
        name="api_device_group_permissions"),
    url(
        r'^api/hubs/(?P<hub>\d+)/registred_devices/'
        r'(?P<device>\d+)/group_permissions/(?P<pk>\d+)/$',
        v.DeviceGroupPermissionsView.as_view(),
        name="api_device_group_permissions_detail"),
    url(
        r'^api/hubs/(?P<hub>\d+)/registred_devices/user_permissions/$',
        v.DeviceUserPermissionListView.as_view(),
        name = "api_device_user_list_permission"
    ),
    url(
        r'^api/hubs/(?P<hub>\d+)/registred_devices/user_permissions/for_user/(?P<user>\d+)/$',
        v.DeviceUserPermissionListView.as_view(),
        name = "api_device_user_list_permission_for_user"
    ),
    url(
        r'^api/hubs/(?P<hub>\d+)/registred_devices/group_permissions/$',
        v.DeviceGroupPermissionListView.as_view(),
        name="api_device_group_list_permission"
    ),
    url(
        r'^api/hubs/(?P<hub>\d+)/registred_devices/group_permissions/for_groups$',
        v.DeviceGroupPermissionListView.as_view(),
        name="api_device_group_list_permission_for_groups"
    ),
    url(r'api/get_me/$', v.GetMe.as_view(), name="api_get_me")
]
