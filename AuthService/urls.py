from django.conf.urls import url
import AuthService.views as v

urlpatterns = [
    url(r'^dashboard/$', v.DashboardView.as_view(), name='dashboard'),
    url(r'^dashboard/users/$', v.UsersView.as_view(), name='users'),
    url(r'^dashboard/hubs/$', v.HubsView.as_view(), name='hubs'),
    url(r'^dashboard/hubs/(?P<hub>\d+)/devices/$', v.DevicesView.as_view(),
        name='devices'),
    url(r'^dashboard/hubs/(?P<hub>\d+)/devices/(?P<device>\d+)/units/$',
        v.DeviceUnitsView.as_view(), name='units'),
    url(r'^dashboard/login/$', v.UserLoginView.as_view(), name='login'),
    url(r'^dashboard/logout/$', v.UserLogoutView.as_view(), name='logout'),

]
