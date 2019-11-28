from django.contrib.auth.forms import UsernameField
from django import forms
import requests
from django.urls import resolve, reverse

from InzynierkaV2.settings import AUTH_SERVICE_ADDRESS


class HubAuthorizationForm(forms.Form):
    username = UsernameField(widget=forms.TextInput(attrs={'autofocus': True}))
    password = forms.CharField(
        label="Password",
        strip=False,
        widget=forms.PasswordInput,
    )

    def clean(self):
        super(HubAuthorizationForm, self).clean()
        response = requests.post(AUTH_SERVICE_ADDRESS + "/api/user_auth/sign_in/", json={
            "username": self.cleaned_data.get("username"),
            "password": self.cleaned_data.get("password")
        })
        if response.status_code != 200:
            raise forms.ValidationError(response.json().get('detail'))

        self.user_token = response.json().get("access")
        self.refresh_token = response.json().get("refresh")
