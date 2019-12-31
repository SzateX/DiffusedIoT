from django.conf.urls import url
import AuthServiceApp.views as v
import AuthServiceApp.api_urls as api_urls

urlpatterns = [
    url(r'^dashboard/$', v.DashboardView.as_view(), name='dashboard'),
    url(r'^dashboard/users/$', v.UsersView.as_view(), name='users'),
    url(r'^dashboard/users/create/$', v.UserCreateView.as_view(), name='user_create'),
    url(r'^dashboard/users/(?P<pk>\d+)/update/$', v.UserUpdateView.as_view(), name='user_update'),
    url(r'^dashboard/users/(?P<pk>\d+)/delete/$', v.UserDeleteView.as_view(), name='user_delete'),
    url(r'^dashboard/users/(?P<pk>\d+)/$', v.UserView.as_view(), name='user_detail'),
    url(r'^dashboard/hubs/$', v.HubsView.as_view(), name='hubs'),
    url(r'^dashboard/hubs/create/$', v.HubCreateView.as_view(), name='hub_create'),
    url(r'^dashboard/hubs/(?P<pk>\d+)/$', v.HubView.as_view(), name='hub_details'),
    url(r'^dashboard/hubs/(?P<pk>\d+)/update/$', v.HubUpdateView.as_view(), name='hub_update'),
    url(r'^dashboard/hubs/(?P<pk>\d+)/delete/$', v.HubDeleteView.as_view(), name='hub_delete'),
    url(r'^dashboard/hubs/(?P<hub>\d+)/reset_key/$', v.HubResetApiKey.as_view(), name='hub_reset_key'),
    url(r'^dashboard/login/$', v.UserLoginView.as_view(), name='login'),
    url(r'^dashboard/logout/$', v.UserLogoutView.as_view(), name='logout'),
    url(r'^dashboard/groups/$', v.GroupsView.as_view(), name='groups'),
    url(r'^dashboard/groups/create/$', v.GroupCreateView.as_view(), name='group_create'),
    url(r'^dashboard/groups/(?P<pk>\d+)/update/$', v.GroupUpdateView.as_view(), name='group_update'),
    url(r'^dashboard/groups/(?P<pk>\d+)/delete/$', v.GroupDeleteView.as_view(), name='group_delete'),
    url(r'^dashboard/groups/(?P<pk>\d+)/$', v.GroupView.as_view(), name='group_detail'),

] + api_urls.api_url_patterns
