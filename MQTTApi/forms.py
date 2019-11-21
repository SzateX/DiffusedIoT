from django.contrib.auth.forms import UsernameField
from django import forms


class HubAuthorizationForm(forms.Form):
    username = UsernameField(widget=forms.TextInput(attrs={'autofocus': True}))
    password = forms.CharField(
        label="Password",
        strip=False,
        widget=forms.PasswordInput,
    )

    def clean(self):
        super(HubAuthorizationForm, self).clean()
        # TODO Do this.

