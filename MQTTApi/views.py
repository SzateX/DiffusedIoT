import requests
from django.contrib.auth.mixins import AccessMixin
from django.contrib.auth.views import redirect_to_login
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.views.generic import FormView, DetailView

from InzynierkaV2.settings import AUTH_SERVICE_ADDRESS
from MQTTApi.forms import HubAuthorizationForm


class HubLoginRequiredMixin(AccessMixin):
    def dispatch(self, request, *args, **kwargs):
        response = requests.post(
            AUTH_SERVICE_ADDRESS + "/api/user_auth/verify_token/",
            json={
                "token": request.COOKIES.get('token'),

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

    def form_valid(self, form):
        response = super(HubLoginView, self).form_valid(form)
        response.set_cookie("user_token", form.user_token)
        response.set_cookie("refresh_token", form.refresh_token)
        return response


class HubDashboard(HubLoginRequiredMixin, DetailView):
    #TODO Przetestować i działać dalej
    pass
