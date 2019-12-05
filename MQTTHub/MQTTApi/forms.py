from django.contrib.auth.forms import UsernameField
from django import forms
import requests
from django.urls import resolve, reverse

from MQTTApi.models import Device
from MQTTApi.services import AuthServiceApi
from MQTTHub.settings import AUTH_SERVICE_ADDRESS


class HubAuthorizationForm(forms.Form):
    username = UsernameField(widget=forms.TextInput(attrs={'autofocus': True}))
    password = forms.CharField(
        label="Password",
        strip=False,
        widget=forms.PasswordInput,
    )

    def clean(self):
        super(HubAuthorizationForm, self).clean()
        username = self.cleaned_data.get("username")
        password = self.cleaned_data.get("password")
        response = AuthServiceApi.sign_in(username, password)

        self.user_token = response.json().get("access")
        self.refresh_token = response.json().get("refresh")


class HubDeviceForm(forms.Form):
    name = forms.CharField()
    type_of_device = forms.ChoiceField(choices=Device.TYPE_CHOICES)
