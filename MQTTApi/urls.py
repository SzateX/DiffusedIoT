from django.conf.urls import url
import MQTTApi.views as v

urlpatterns = [
    url(r'^login/$', v.HubLoginView.as_view(), name='hub_login'),
    url(r'^logout/$', v.HubLogoutView.as_view(), name='hub_logout'),
    url(r'^dashboard/$', v.HubDashboard.as_view(), name='hub_dashboard'),
    url(r'^dashboard/hub/(?P<hub>\d+)/$', v.HubDeviceView.as_view(), name='hub_devices')
]
