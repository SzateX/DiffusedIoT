import json

import requests
from django.contrib.auth.mixins import AccessMixin
from django.contrib.auth.views import redirect_to_login
from django.http import HttpResponseRedirect
from django.shortcuts import resolve_url, redirect, render
from django.utils import timezone
from django.utils.http import is_safe_url
from django.views.generic import FormView, TemplateView, RedirectView

from MQTTApi import serializers
from MQTTApi.enums import UnitType
from MQTTApi.models import TemperatureUnitValue, SwitchUnitValue, \
    HumidityUnitValue
from MQTTApi.services import AuthServiceApi, InternalApi
from MQTTHub import settings
from MQTTHub.settings import AUTH_SERVICE_ADDRESS
from MQTTApi.forms import HubAuthorizationForm, HubDeviceForm, \
    UserPermissionForm, GroupPermissionForm, UnitForm, \
    TemperatureUnitValueForm, HumidityUnitValueForm, SwitchUnitValueForm


def handler500(request):
    if 'user_token' in request.COOKIES:
        del request.COOKIES['user_token']
    if 'refresh_token' in request.COOKIES:
        del request.COOKIES['refresh_token']
    response = render(request, '500.html', status=500)
    response.delete_cookie("user_token")
    response.delete_cookie("refresh_token")


class HubLoginRequiredMixin(AccessMixin):
    def dispatch(self, request, *args, **kwargs):
        if not AuthServiceApi.verify_token(request):
            return self.handle_no_permission()
        self.user = AuthServiceApi.get_me(request.COOKIES.get('user_token'))
        return super().dispatch(request, *args, **kwargs)

    def handle_no_permission(self):
        return redirect_to_login(self.request.get_full_path(),
                                 self.get_login_url(),
                                 self.get_redirect_field_name())


class HubUserPassesTestMixin(AccessMixin):
    def dispatch(self, request, *args, **kwargs):
        if not AuthServiceApi.verify_token(request):
            return self.handle_no_permission()
        self.user = AuthServiceApi.get_me(request.COOKIES.get('user_token'))
        if not self.test_func():
            return self.handle_no_permission()
        return super().dispatch(request, *args, **kwargs)

    def test_func(self):
        raise NotImplementedError(
            '{0} is missing the implementation of the test_func() method.'.format(
                self.__class__.__name__)
        )

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

    def get(self, request, *args, **kwargs):
        if 'user_token' in request.COOKIES:
            del request.COOKIES['user_token']
        if 'refresh_token' in request.COOKIES:
            del request.COOKIES['refresh_token']
        response = super(HubLoginView, self).get(request, *args, **kwargs)
        response.delete_cookie("user_token")
        response.delete_cookie("refresh_token")
        return response

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

    def get(self, request, *args, **kwargs):
        self.hubs = AuthServiceApi.get_hubs()
        return super(HubDashboard, self).get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super(HubDashboard, self).get_context_data(**kwargs)
        context['hubs'] = self.hubs
        print(self.hubs)
        return context


class HubDeviceView(HubLoginRequiredMixin, TemplateView):
    template_name = 'MQTTApi/device.html'
    login_url = '/hub/login'

    def get(self, request, *args, **kwargs):
        hub = AuthServiceApi.get_hub(int(kwargs.get('hub')))
        self.hub = hub
        self.devices = InternalApi.get_devices(self.request.COOKIES.get('user_token'), hub)
        return super(HubDeviceView, self).get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super(HubDeviceView, self).get_context_data(**kwargs)
        context['devices'] = self.devices
        context['hub'] = self.hub
        return context


class AddDeviceView(HubUserPassesTestMixin, FormView):
    form_class = HubDeviceForm
    template_name = 'MQTTApi/devices/add.html'
    login_url = '/hub/login'

    def form_valid(self, form):
        hub = AuthServiceApi.get_hub(self.kwargs.get('hub'))
        token = self.request.COOKIES.get(
                    'user_token')
        InternalApi.save_device(token, hub, form)
        return HttpResponseRedirect(self.get_success_url())

    def test_func(self):
        return self.user['is_staff']

    def get_success_url(self):
        return '/hub/dashboard/hub/%d/' % int(self.kwargs.get('hub'))


class DeleteDeviceView(HubUserPassesTestMixin, RedirectView):
    login_url = '/hub/login/'

    def test_func(self):
        return self.user['is_staff']

    def get(self, *args, **kwargs):
        hub = AuthServiceApi.get_hub(self.kwargs.get('hub'))
        token = self.request.COOKIES.get(
            'user_token')
        InternalApi.delete_device(token, hub, self.kwargs.get('pk'))
        return redirect(self.get_success_url())

    def get_success_url(self):
        return '/hub/dashboard/hub/%d/' % int(self.kwargs.get('hub'))


class UpdateDeviceView(HubUserPassesTestMixin, FormView):
    form_class = HubDeviceForm
    template_name = 'MQTTApi/devices/add.html'
    login_url = '/hub/login/'

    def get_context_data(self, **kwargs):
        context = super(UpdateDeviceView, self).get_context_data(**kwargs)
        context['form'] = self.get_form_class()(initial=self.object)
        context['update'] = True
        return context

    def get(self, request, *args, **kwargs):
        token = self.request.COOKIES.get('user_token')
        hub = AuthServiceApi.get_hub(kwargs['hub'])
        self.object = InternalApi.get_device(token, hub, kwargs['pk'])
        return super(UpdateDeviceView, self).get(request, *args, **kwargs)

    def form_valid(self, form):
        token = self.request.COOKIES.get('user_token')
        hub = AuthServiceApi.get_hub(self.kwargs['hub'])
        device_id = int(self.kwargs.get('pk'))
        InternalApi.update_device(token, hub, device_id, form)
        return HttpResponseRedirect(self.get_success_url())

    def test_func(self):
        return self.user['is_staff']

    def get_success_url(self):
        return '/hub/dashboard/hub/%d/' % int(self.kwargs.get('hub'))


class DevicePermissionsView(HubUserPassesTestMixin, TemplateView):
    template_name = "MQTTApi/permissions/list.html"
    login_url = '/hub/login'

    def test_func(self):
        return self.user['is_staff']

    def convert_users_to_usernames(self, permissions, users):
        perms = []
        for permission in permissions:
            for user in users:
                print(permission)
                print(user)
                if user['pk'] == permission['user']:
                    permission['user'] = user
                    perms.append(permission)
                    break
        return perms

    def convert_gropus_to_groupnames(self, permissions, groups):
        perms = []
        for permission in permissions:
            for group in groups:
                if group['pk'] == permission['group']:
                    permission['group'] = group
                    perms.append(permission)
                    break
        return perms

    def get(self, request, *args, **kwargs):
        token = self.request.COOKIES.get('user_token')
        hub = AuthServiceApi.get_hub(kwargs['hub'])
        device = InternalApi.get_device(token, hub, kwargs['pk'])
        self.device = device
        self.users = AuthServiceApi.get_users()
        self.groups = AuthServiceApi.get_groups()
        self.user_permissions = AuthServiceApi.get_device_user_permissions(hub['pk'], device['pk'])
        self.group_permissions = AuthServiceApi.get_device_group_permissions(hub['pk'], device['pk'])
        return super(DevicePermissionsView, self).get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super(DevicePermissionsView, self).get_context_data(**kwargs)
        context['user_permissions'] = self.convert_users_to_usernames(self.user_permissions, self.users)
        context['group_permissions'] = self.convert_gropus_to_groupnames(self.group_permissions, self.groups)
        context['device'] = self.device
        return context


class AddDeviceUserPermissionView(HubUserPassesTestMixin, FormView):
    form_class = UserPermissionForm
    template_name = 'MQTTApi/permissions/add.html'
    login_url = '/hub/login/'

    def test_func(self):
        return self.user['is_staff']
    
    def get(self, request, *args, **kwargs):
        self.users = AuthServiceApi.get_users()
        return super(AddDeviceUserPermissionView, self).get(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        self.users = AuthServiceApi.get_users()
        return super(AddDeviceUserPermissionView, self).post(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super(AddDeviceUserPermissionView, self).get_context_data(**kwargs)
        # context['form'] = self.get_form_class()(user_list=self.users)
        return context

    def get_form(self, form_class=None):
        if form_class is None:
            form_class = self.get_form_class()
        return form_class(self.users, **self.get_form_kwargs())

    def form_valid(self, form):
        hub = AuthServiceApi.get_hub(self.kwargs['hub'])
        device_id = int(self.kwargs.get('pk'))
        form.cleaned_data['user'] = int(form.cleaned_data['user'])
        form.cleaned_data['device'] = device_id
        AuthServiceApi.add_device_user_permission(hub['pk'], device_id, form.cleaned_data)
        return HttpResponseRedirect(self.get_success_url())
    
    def form_invalid(self, form):
        return super(AddDeviceUserPermissionView, self).form_invalid(form)

    def get_success_url(self):
        return '/hub/dashboard/hub/%s/device/%s/permissions/' % (self.kwargs.get('hub'), self.kwargs.get('pk'))
        

class AddDeviceGroupPermissionView(HubUserPassesTestMixin, FormView):
    form_class = GroupPermissionForm
    template_name = 'MQTTApi/permissions/add.html'
    login_url = '/hub/login/'

    def test_func(self):
        return self.user['is_staff']

    def get(self, request, *args, **kwargs):
        self.groups = AuthServiceApi.get_groups()
        return super(AddDeviceGroupPermissionView, self).get(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        self.groups = AuthServiceApi.get_groups()
        return super(AddDeviceGroupPermissionView, self).post(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super(AddDeviceGroupPermissionView, self).get_context_data(**kwargs)
        # context['form'] = self.get_form_class()(group_list=self.groups)
        context['group'] = True
        return context

    def form_valid(self, form):
        hub = AuthServiceApi.get_hub(self.kwargs['hub'])
        device_id = int(self.kwargs.get('pk'))
        form.cleaned_data['group'] = int(form.cleaned_data['group'])
        form.cleaned_data['device'] = device_id
        AuthServiceApi.add_device_group_permission(hub['pk'], device_id, form.cleaned_data)
        return HttpResponseRedirect(self.get_success_url())

    def get_success_url(self):
        return '/hub/dashboard/hub/%s/device/%s/permissions/' % (self.kwargs.get('hub'), self.kwargs.get('pk'))

    def get_form(self, form_class=None):
        if form_class is None:
            form_class = self.get_form_class()
        return form_class(self.groups, **self.get_form_kwargs())


class UpdateDeviceUserPermissionView(HubUserPassesTestMixin, FormView):
    form_class = UserPermissionForm
    template_name = 'MQTTApi/permissions/add.html'
    login_url = '/hub/login/'

    def test_func(self):
        return self.user['is_staff']

    def get(self, request, *args, **kwargs):
        self.users = AuthServiceApi.get_users()
        hub_id = kwargs.get('hub')
        device_id = kwargs.get('device')
        permission_id = kwargs.get('pk')
        self.object = AuthServiceApi.get_device_user_permission(hub_id,
                                                                device_id,
                                                                permission_id)
        return super(UpdateDeviceUserPermissionView, self).get(request, *args,
                                                            **kwargs)

    def post(self, request, *args, **kwargs):
        self.users = AuthServiceApi.get_users()
        hub_id = kwargs.get('hub')
        device_id = kwargs.get('device')
        permission_id = kwargs.get('pk')
        self.object = AuthServiceApi.get_device_user_permission(hub_id,
                                                                device_id,
                                                                permission_id)
        return super(UpdateDeviceUserPermissionView, self).post(request, *args,
                                                             **kwargs)

    def get_context_data(self, **kwargs):
        context = super(UpdateDeviceUserPermissionView, self).get_context_data(
            **kwargs)
        # context['form'] = self.get_form_class()(user_list=self.users)
        context['update'] = True
        return context

    def get_form(self, form_class=None):
        if form_class is None:
            form_class = self.get_form_class()
        return form_class(self.users, **self.get_form_kwargs())

    def form_valid(self, form):
        hub = AuthServiceApi.get_hub(self.kwargs['hub'])
        device_id = int(self.kwargs.get('device'))
        permission_id = self.kwargs.get('pk')
        form.cleaned_data['user'] = int(form.cleaned_data['user'])
        form.cleaned_data['device'] = device_id
        AuthServiceApi.update_device_user_permission(hub['pk'], device_id, permission_id,
                                                  form.cleaned_data)
        return HttpResponseRedirect(self.get_success_url())

    def form_invalid(self, form):
        return super(UpdateDeviceUserPermissionView, self).form_invalid(form)

    def get_success_url(self):
        return '/hub/dashboard/hub/%s/device/%s/permissions/' % (
        self.kwargs.get('hub'), self.kwargs.get('device'))

    def get_initial(self):
        return self.object


class UpdateDeviceGroupPermissionView(HubUserPassesTestMixin, FormView):
    form_class = GroupPermissionForm
    template_name = 'MQTTApi/permissions/add.html'
    login_url = '/hub/login/'

    def test_func(self):
        return self.user['is_staff']

    def get(self, request, *args, **kwargs):
        self.groups = AuthServiceApi.get_groups()
        hub_id = kwargs.get('hub')
        device_id = kwargs.get('device')
        permission_id = kwargs.get('pk')
        self.object = AuthServiceApi.get_device_group_permission(hub_id,
                                                                device_id,
                                                                permission_id)
        return super(UpdateDeviceGroupPermissionView, self).get(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        self.groups = AuthServiceApi.get_groups()
        hub_id = kwargs.get('hub')
        device_id = kwargs.get('device')
        permission_id = kwargs.get('pk')
        self.object = AuthServiceApi.get_device_group_permission(hub_id,
                                                                device_id,
                                                                permission_id)

        return super(UpdateDeviceGroupPermissionView, self).post(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super(UpdateDeviceGroupPermissionView, self).get_context_data(**kwargs)
        # context['form'] = self.get_form_class()(group_list=self.groups)
        context['update'] = True
        context['group'] = True
        return context

    def form_valid(self, form):
        hub = AuthServiceApi.get_hub(self.kwargs['hub'])
        device_id = int(self.kwargs.get('device'))
        permission_id = self.kwargs.get('pk')
        form.cleaned_data['group'] = int(form.cleaned_data['group'])
        form.cleaned_data['device'] = device_id
        AuthServiceApi.update_device_group_permission(hub['pk'], device_id, permission_id, form.cleaned_data)
        return HttpResponseRedirect(self.get_success_url())

    def get_success_url(self):
        return '/hub/dashboard/hub/%s/device/%s/permissions/' % (self.kwargs.get('hub'), self.kwargs.get('device'))

    def get_form(self, form_class=None):
        if form_class is None:
            form_class = self.get_form_class()
        return form_class(self.groups, **self.get_form_kwargs())

    def get_initial(self):
        return self.object


class DeleteDeviceUserPermissionView(HubUserPassesTestMixin, RedirectView):
    def test_func(self):
        return self.user['is_staff']

    def get(self, *args, **kwargs):
        hub_id = kwargs.get('hub')
        device_id = kwargs.get('device')
        permission_id = kwargs.get('pk')
        AuthServiceApi.delete_device_user_permission(hub_id, device_id, permission_id)
        return redirect(self.get_success_url())

    def get_success_url(self):
        s = '/hub/dashboard/hub/%s/device/%s/permissions/' % (
        self.kwargs.get('hub'), self.kwargs.get('device'))
        return s


class DeleteDeviceGroupPermissionView(HubUserPassesTestMixin, RedirectView):
    def test_func(self):
        return self.user['is_staff']

    def get(self, *args, **kwargs):
        hub_id = kwargs.get('hub')
        device_id = kwargs.get('device')
        permission_id = kwargs.get('pk')
        AuthServiceApi.delete_device_group_permission(hub_id, device_id, permission_id)
        return redirect(self.get_success_url())

    def get_success_url(self):
        return '/hub/dashboard/hub/%s/device/%s/permissions/' % (self.kwargs.get('hub'), self.kwargs.get('device'))


class DeviceUnitsView(HubLoginRequiredMixin, TemplateView):
    login_url = '/hub/login/'
    template_name = 'MQTTApi/units/list.html'

    def get(self, request, *args, **kwargs):
        hub = AuthServiceApi.get_hub(self.kwargs.get('hub'))
        self.device = InternalApi.get_device(self.request.COOKIES.get('user_token'), hub, self.kwargs.get('pk'))
        self.units = InternalApi.get_units(self.request.COOKIES.get('user_token'), hub, self.kwargs.get('pk'))
        self.user = AuthServiceApi.get_me(self.request.COOKIES.get('user_token'))
        return super(DeviceUnitsView, self).get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super(DeviceUnitsView, self).get_context_data(**kwargs)
        context['device'] = self.device
        context['units'] = self.units
        context['user'] = self.user
        return context


class AddDeviceUnitView(HubUserPassesTestMixin, FormView):
    login_url = '/hub/login/'
    template_name = 'MQTTApi/units/add.html'
    form_class = UnitForm

    def test_func(self):
        return self.user['is_staff']

    def form_valid(self, form):
        hub = AuthServiceApi.get_hub(self.kwargs.get('hub'))
        device_id = self.kwargs.get('pk')
        token = self.request.COOKIES.get(
            'user_token')
        InternalApi.add_unit(token, hub, device_id, form.cleaned_data)
        return super(AddDeviceUnitView, self).form_valid(form)

    def get_success_url(self):
        return '/hub/dashboard/hub/%s/device/%s/units/' % (self.kwargs.get('hub'), self.kwargs.get('pk'))


class UpdateDeviceUnitView(HubUserPassesTestMixin, FormView):
    login_url = '/hub/login/'
    template_name = 'MQTTApi/units/add.html'
    form_class = UnitForm

    def test_func(self):
        return self.user['is_staff']

    def form_valid(self, form):
        hub = AuthServiceApi.get_hub(self.kwargs.get('hub'))
        device_id = self.kwargs.get('device')
        pk = self.kwargs.get('pk')
        token = self.request.COOKIES.get(
            'user_token')
        InternalApi.update_unit(token, hub, device_id, pk, form.cleaned_data)
        return super(UpdateDeviceUnitView, self).form_valid(form)

    def get_context_data(self, **kwargs):
        context = super(UpdateDeviceUnitView, self).get_context_data(**kwargs)
        context['form'] = self.get_form_class()(initial=self.object)
        context['update'] = True
        return context
        
    def get(self, request, *args, **kwargs):
        hub = AuthServiceApi.get_hub(self.kwargs.get('hub'))
        device_id = self.kwargs.get('device')
        token = self.request.COOKIES.get(
            'user_token')
        self.object = InternalApi.get_unit(token, hub, device_id, self.kwargs.get('pk'))
        return super(UpdateDeviceUnitView, self).get(request, *args, **kwargs)
    
    def post(self, request, *args, **kwargs):
        hub = AuthServiceApi.get_hub(self.kwargs.get('hub'))
        device_id = self.kwargs.get('device')
        token = self.request.COOKIES.get(
            'user_token')
        self.object = InternalApi.get_unit(token, hub, device_id,
                                           self.kwargs.get('pk'))
        return super(UpdateDeviceUnitView, self).post(request, *args, **kwargs)

    def get_success_url(self):
        return '/hub/dashboard/hub/%s/device/%s/units/' % (self.kwargs.get('hub'), self.kwargs.get('device'))


class DeleteDeviceUnitView(HubUserPassesTestMixin, RedirectView):
    login_url = '/hub/login/'

    def test_func(self):
        return self.user['is_staff']

    def get(self, *args, **kwargs):
        hub = AuthServiceApi.get_hub(self.kwargs.get('hub'))
        device_id = self.kwargs.get('device')
        token = self.request.COOKIES.get(
            'user_token')
        InternalApi.delete_unit(token, hub, device_id, self.kwargs.get('pk'))
        return redirect(self.get_success_url())

    def get_success_url(self):
        return '/hub/dashboard/hub/%s/device/%s/units/' % (self.kwargs.get('hub'), self.kwargs.get('device'))


class ConnectUnitHubSelectView(HubUserPassesTestMixin, TemplateView):
    login_url = '/hub/login/'
    template_name = 'MQTTApi/connected_units/hub_select.html'

    def test_func(self):
        return self.user['is_staff']

    def get(self, request, *args, **kwargs):
        self.hubs = AuthServiceApi.get_hubs()
        return super(ConnectUnitHubSelectView, self).get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super(ConnectUnitHubSelectView, self).get_context_data(**kwargs)
        context['hubs'] = self.hubs
        return context


class ConnectUnitDeviceSelectView(HubUserPassesTestMixin, TemplateView):
    login_url = '/hub/login/'
    template_name = 'MQTTApi/connected_units/device_select.html'

    def test_func(self):
        return self.user['is_staff']

    def get(self, request, *args, **kwargs):
        token = self.request.COOKIES.get(
            'user_token')
        self.hub = AuthServiceApi.get_hub(self.kwargs.get('dest_hub'))
        self.devices = InternalApi.get_devices(token, self.hub)
        return super(ConnectUnitDeviceSelectView, self).get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super(ConnectUnitDeviceSelectView, self).get_context_data(**kwargs)
        context['hub'] = self.hub
        context['devices'] = self.devices
        return context


class ConnectUnitSelectUnitView(HubUserPassesTestMixin, TemplateView):
    login_url = '/hub/login/'
    template_name = 'MQTTApi/connected_units/unit_select.html'

    def test_func(self):
        return self.user['is_staff']

    def get(self, request, *args, **kwargs):
        token = self.request.COOKIES.get('user_token')
        self.hub = AuthServiceApi.get_hub(self.kwargs.get('dest_hub'))
        self.device = InternalApi.get_device(token, self.hub, self.kwargs.get('dest_device'))
        self.units = InternalApi.get_units(token, self.hub, self.device['pk'])
        return super(ConnectUnitSelectUnitView, self).get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super(ConnectUnitSelectUnitView, self).get_context_data(**kwargs)
        context['hub'] = self.hub
        context['device'] = self.device
        context['units'] = self.units
        return context


class ConnectedUnitList(HubUserPassesTestMixin, TemplateView):
    login_url = '/hub/login/'
    template_name = 'MQTTApi/connected_units/list.html'

    def test_func(self):
        return self.user['is_staff']

    def get(self, request, *args, **kwargs):
        token = self.request.COOKIES.get('user_token')
        self.hub = AuthServiceApi.get_hub(self.kwargs.get('hub'))
        self.device = InternalApi.get_device(token, self.hub,
                                             self.kwargs.get('device'))
        self.unit = InternalApi.get_unit(token, self.hub,
                                           self.device['pk'], self.kwargs.get('pk'))
        self.connected_units = InternalApi.get_connected_units_with_unit(token, self.hub, self.unit['pk'])
        return super(ConnectedUnitList, self).get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super(ConnectedUnitList, self).get_context_data(**kwargs)
        context['hub'] = self.hub
        context['device'] = self.device
        context['unit'] = self.unit
        context['connected_units'] = self.connected_units
        return context


class ConnectUnitConfirmView(HubUserPassesTestMixin, TemplateView):
    login_url = '/hub/login/'
    template_name = 'MQTTApi/connected_units/confirm.html'

    def test_func(self):
        return self.user['is_staff']

    def get(self, request, *args, **kwargs):
        token = self.request.COOKIES.get('user_token')
        self.hub = AuthServiceApi.get_hub(self.kwargs.get('dest_hub'))
        self.device = InternalApi.get_device(token, self.hub,
                                             self.kwargs.get('dest_device'))
        self.unit = InternalApi.get_unit(token, self.hub,
                                           self.device['pk'], self.kwargs.get('dest_unit'))
        context = self.get_context_data()
        return self.render_to_response(context)

    def post(self, request, *args, **kwargs):
        token = self.request.COOKIES.get('user_token')
        hub = AuthServiceApi.get_hub(self.kwargs.get('hub'))
        InternalApi.add_connected_unit(token, hub, {
            'from_unit': int(self.kwargs.get('pk')),
            'dest_hub': int(self.kwargs.get('dest_hub')),
            'dest_device': int(self.kwargs.get('dest_device')),
            'dest_unit': int(self.kwargs.get('dest_unit'))
        })
        return HttpResponseRedirect(self.get_success_url())

    def get_context_data(self, **kwargs):
        context = super(ConnectUnitConfirmView, self).get_context_data(**kwargs)
        context['hub'] = self.hub
        context['device'] = self.device
        context['unit'] = self.unit
        return context

    def get_success_url(self):
        return '/hub/dashboard/hub/%s/device/%s/units/%s/connected_units/' % (self.kwargs.get('hub'), self.kwargs.get('device'), self.kwargs.get('pk'))


class DeleteConnectedUnitView(HubUserPassesTestMixin, RedirectView):
    login_url = '/hub/login/'

    def test_func(self):
        return self.user['is_staff']

    def get(self, *args, **kwargs):
        hub = AuthServiceApi.get_hub(self.kwargs.get('hub'))
        token = self.request.COOKIES.get(
            'user_token')
        InternalApi.delete_connected_unit(token, hub, self.kwargs.get('pk'))
        return redirect(self.get_success_url())

    def get_success_url(self):
        return '/hub/dashboard/hub/%s/device/%s/units/%s/connected_units/' % (self.kwargs.get('hub'), self.kwargs.get('device'), self.kwargs.get('unit'))


class UnitDataView(HubLoginRequiredMixin, FormView):
    login_url = '/hub/login/'
    template_name = 'MQTTApi/units/data.html'

    def get(self, request, *args, **kwargs):
        hub = AuthServiceApi.get_hub(self.kwargs.get('hub'))
        self.hub = hub
        token = self.request.COOKIES.get('user_token')
        self.device = InternalApi.get_device(token, self.hub,
                                             self.kwargs.get('device'))
        self.unit = InternalApi.get_unit(token, hub, self.kwargs.get('device'), self.kwargs.get('pk'))
        self.data = InternalApi.get_data_from_unit(token, hub, self.kwargs.get('device'), self.kwargs.get('pk'))
        self.has_write_perms = AuthServiceApi.has_write_permission(hub['pk'], self.kwargs.get('device'), self.user['pk'])
        return super(UnitDataView, self).get(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        self.hub = AuthServiceApi.get_hub(self.kwargs.get('hub'))
        self.token = self.request.COOKIES.get('user_token')
        self.device = InternalApi.get_device(self.token, self.hub, self.kwargs.get('device'))
        self.unit = InternalApi.get_unit(self.token, self.hub, self.kwargs.get('device'),
                                         self.kwargs.get('pk'))
        self.data = InternalApi.get_data_from_unit(self.token, self.hub,
                                                   self.kwargs.get('device'),
                                                   self.kwargs.get('pk'))
        self.has_write_perms = AuthServiceApi.has_write_permission(self.hub['pk'],
                                                                   self.kwargs.get(
                                                                       'device'),
                                                                   self.user[
                                                                       'pk'])
        if not self.has_write_perms['has_write_perm']:
            return HttpResponseRedirect(self.get_success_url())
        return super(UnitDataView, self).post(request, *args, **kwargs)

    def get_form_class(self):
        if self.unit['type_of_unit'] == UnitType.TEMPERATURE_UNIT:
            return TemperatureUnitValueForm
        elif self.unit['type_of_unit'] == UnitType.SWITCH_UNIT:
            return SwitchUnitValueForm
        elif self.unit['type_of_unit'] == UnitType.HUMIDITY_UNIT:
            return HumidityUnitValueForm
        return None

    def get_context_data(self, **kwargs):
        context = super(UnitDataView, self).get_context_data(**kwargs)
        context['data'] = self.data
        context['hub'] = self.hub
        context['device'] = self.device
        context['unit'] = self.unit
        context['has_write_perms'] = self.has_write_perms['has_write_perm']
        context['has_unit'] = self.unit['type_of_unit'] in [UnitType.HUMIDITY_UNIT, UnitType.TEMPERATURE_UNIT]
        return context

    def form_valid(self, form):
        if self.unit['type_of_unit'] == UnitType.TEMPERATURE_UNIT:
            obj = TemperatureUnitValue(timestamp=timezone.now(), incoming=True, **form.cleaned_data)
            serializer_obj = json.dumps(
                serializers.TemperatureUnitValueSerializer(obj).data)
            prepared_objs = [json.dumps({'data': serializer_obj,
                              'type': 'TemperatureUnitValue'})]
        elif self.unit['type_of_unit'] == UnitType.SWITCH_UNIT:
            obj = SwitchUnitValue(timestamp=timezone.now(), incoming=True,
                                       **form.cleaned_data)
            serializer_obj = json.dumps(
                serializers.SwitchUnitValueSerializer(obj).data)
            prepared_objs = [{'data': serializer_obj,
                              'type': 'SwitchUnitValue'}]
        elif self.unit['type_of_unit'] == UnitType.HUMIDITY_UNIT:
            obj = HumidityUnitValue(timestamp=timezone.now(), incoming=True,
                                       **form.cleaned_data)
            serializer_obj = json.dumps(
                serializers.HumidityUnitValueSerializer(obj).data)
            prepared_objs = [{'data': serializer_obj,
                              'type': 'HumidityUnitValue'}]
        else:
            raise Exception("Invalid Type Of Device")
        payload = {
            'device': int(self.kwargs.get('device')),
            'unit': self.unit['pk'],
            'data': prepared_objs
        }
        InternalApi.send_data_to_unit(self.hub, payload)

        connected_units = InternalApi.get_connected_units_with_unit(self.token, self.hub, self.unit['pk'])
        for connected_unit in connected_units:
            payload = {
                'device': connected_unit['dest_device'],
                'unit': connected_unit['dest_unit'],
                'data': prepared_objs
            }
            hub = AuthServiceApi.get_hub(connected_unit['dest_hub'])
            InternalApi.send_data_to_unit(hub, payload)

        return HttpResponseRedirect(self.get_success_url())

    def get_success_url(self):
        return '/hub/dashboard/hub/%s/device/%s/units/%s/data/' % (
        self.kwargs.get('hub'), self.kwargs.get('device'),
        self.kwargs.get('pk'))