from django.contrib.auth.forms import UsernameField
from django import forms
import requests
from django.urls import resolve, reverse

from MQTTApi.models import Device, DeviceUnit, TemperatureUnitValue, \
    HumidityUnitValue, SwitchUnitValue
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


class UserPermissionForm(forms.Form):
    read_permission = forms.BooleanField(required=False, help_text="This allow user to display device.")
    write_permission = forms.BooleanField(required=False, help_text="This allow to write data to units.")
    user = forms.TypedChoiceField(coerce=int)

    def __init__(self, user_list=None, *args, **kwargs):
        super(UserPermissionForm, self).__init__(*args, **kwargs)
        if user_list:
            # self.fields['user'] = forms.ChoiceField(choices=((user['pk'], user['username']) for user in user_list))
            self.fields['user'].choices = ((int(user['pk']), user['username']) for user in user_list)


class GroupPermissionForm(forms.Form):
    read_permission = forms.BooleanField(required=False, help_text="This allow user to display device.")
    write_permission = forms.BooleanField(required=False, help_text="This allow to write data to units.")
    group = forms.TypedChoiceField(coerce=int)

    def __init__(self, group_list=None, *args, **kwargs):
        super(GroupPermissionForm, self).__init__(*args, **kwargs)
        if group_list:
            print(group_list)
            self.fields['group'].choices = ((int(group['pk']), group['name']) for group in group_list)


class UnitForm(forms.Form):
    name = forms.CharField(max_length=200)
    direction = forms.ChoiceField(choices=DeviceUnit.DIRECTION_CHOICES)
    type_of_unit = forms.ChoiceField(choices=DeviceUnit.TYPE_CHOICES)


class TemperatureUnitValueForm(forms.ModelForm):
    class Meta:
        model = TemperatureUnitValue
        fields = ('value', 'unit')


class HumidityUnitValueForm(forms.ModelForm):
    class Meta:
        model = HumidityUnitValue
        fields = ('value', 'unit')


class SwitchUnitValueForm(forms.ModelForm):
    class Meta:
        model = SwitchUnitValue
        fields = ('value', )