from django.conf.urls import url
import MQTTApi.views as v

urlpatterns = [
    url(r'^login/$', v.HubLoginView.as_view(), name='hub_login'),
]
