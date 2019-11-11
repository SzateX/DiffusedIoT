from django.conf.urls import url
import AuthService.api_views as v

api_url_patterns = [
    url(r'^api/user_auth/sign_in/$', v.APIUserLoginView.as_view(), name='api_user_sign_in'),
    url(r'^api/user_auth/refresh_token/$', v.APIRefreshUserToken.as_view(), name='api_user_refresh_token'),
    url(r'^api/user_auth/verify_token/$', v.APIVerifyUserToken.as_view(), name='api_user_verify_token'),
    url(r'^api/hubs/$', v.HubListView.as_view(), name='api_hubs'),
    url(r'^api/hubs/validate_api_key/(?P<pk>\d+)/$', v.HubValidApiKeyView.as_view(), name='api_key_validate')
]