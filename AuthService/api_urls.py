from django.conf.urls import url
import AuthService.api_views as v

api_url_patterns = [
    url(r'^api/hubs/$', v.HubListView.as_view(), name='api_hubs'),
    url(r'^api/validate_api_key/(?P<pk>\d+)/$', v.HubValidApiKeyView.as_view(), name='api_key_validate')
]