from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.views.generic import FormView

from MQTTApi.forms import HubAuthorizationForm


class HubLoginView(FormView):
    form_class = HubAuthorizationForm
    template_name = 'MQTTApi/login.html'
    success_url = "/"