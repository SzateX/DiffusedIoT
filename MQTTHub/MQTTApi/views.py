import requests
from django.contrib.auth.mixins import AccessMixin
from django.contrib.auth.views import redirect_to_login
from django.http import HttpResponseRedirect
from django.shortcuts import resolve_url
from django.utils.http import is_safe_url
from django.views.generic import FormView, TemplateView

from MQTTHub import settings
from MQTTHub.settings import AUTH_SERVICE_ADDRESS
from MQTTApi.forms import HubAuthorizationForm


class HubLoginRequiredMixin(AccessMixin):
    def dispatch(self, request, *args, **kwargs):
        response = requests.post(
            AUTH_SERVICE_ADDRESS + "/api/user_auth/verify_token/",
            json={
                "token": request.COOKIES.get('user_token'),

            })
        if response.status_code != 200:
            return self.handle_no_permission()
        return super().dispatch(request, *args, **kwargs)

    def handle_no_permission(self):
        return redirect_to_login(self.request.get_full_path(),
                                 self.get_login_url(),
                                 self.get_redirect_field_name())


class HubLoginView(FormView):
    form_class = HubAuthorizationForm
    template_name = 'MQTTApi/login.html'
    success_url = "/"
    redirect_field_name = 'next'
    success_url_allowed_hosts = set()

    def form_valid(self, form):
        response = super(HubLoginView, self).form_valid(form)
        response.set_cookie("user_token", form.user_token)
        response.set_cookie("refresh_token", form.refresh_token)
        return response

    def get_redirect_url(self):
        """Return the user-originating redirect URL if it's safe."""
        redirect_to = self.request.POST.get(
            self.redirect_field_name,
            self.request.GET.get(self.redirect_field_name, '')
        )
        url_is_safe = is_safe_url(
            url=redirect_to,
            allowed_hosts=self.get_success_url_allowed_hosts(),
            require_https=self.request.is_secure(),
        )
        return redirect_to if url_is_safe else ''

    def get_success_url(self):
        url = self.get_redirect_url()
        return url or resolve_url(settings.LOGIN_REDIRECT_URL)

    def get_success_url_allowed_hosts(self):
        return {self.request.get_host(), *self.success_url_allowed_hosts}


class HubLogoutView(TemplateView):
    next_page = "/hub/dashboard/"

    def dispatch(self, request, *args, **kwargs):
        response = HttpResponseRedirect(self.next_page)
        response.delete_cookie("user_token")
        response.delete_cookie("refresh_token")
        return response


class HubDashboard(HubLoginRequiredMixin, TemplateView):
    template_name = 'MQTTApi/dashboard.html'
    login_url = '/hub/login'

    def get_hubs(self):
        response = requests.get(
            AUTH_SERVICE_ADDRESS + "/api/hubs/")

        if response.status_code != 200:
            raise Exception("Error in connection with AuthService: "
                            + response.content)

        return response.json()

    def get(self, request, *args, **kwargs):
        self.hubs = self.get_hubs()
        return super(HubDashboard, self).get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super(HubDashboard, self).get_context_data(**kwargs)
        context['hubs'] = self.hubs
        print(self.hubs)
        return context


class HubDeviceView(HubLoginRequiredMixin, TemplateView):
    template_name = 'MQTTApi/device.html'
    login_url = '/hub/login'

    def get_hub(self, hub_id):
        response = requests.get(
            AUTH_SERVICE_ADDRESS + "/api/hub/%d/" % hub_id,
        )

        if response.status_code != 200:
            raise Exception("Error in connection with AuthService: "
                            + response.text)

        return response.json()

    def get_devices(self, hub):
        response = requests.get(
            hub['private_address'] + "/hub/internal_api/devices_for_user/",
            headers={
                'Authorization': "Bearer " + self.request.COOKIES.get(
                    'user_token')
            }
        )

        if response.status_code != 200:
            raise Exception("Error in connection with AuthService: "
                            + response.text)

        return response.json()

    def get(self, request, *args, **kwargs):
        hub = self.get_hub(int(kwargs.get('hub')))
        self.devices = self.get_devices(hub)
        return super(HubDeviceView, self).get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super(HubDeviceView, self).get_context_data(**kwargs)
        context['devices'] = self.devices
        return context

