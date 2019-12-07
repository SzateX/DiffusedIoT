import requests
from django.contrib.auth.mixins import AccessMixin
from django.contrib.auth.views import redirect_to_login
from django.http import HttpResponseRedirect
from django.shortcuts import resolve_url
from django.utils.http import is_safe_url
from django.views.generic import FormView, TemplateView

from MQTTApi.services import AuthServiceApi, InternalApi
from MQTTHub import settings
from MQTTHub.settings import AUTH_SERVICE_ADDRESS
from MQTTApi.forms import HubAuthorizationForm, HubDeviceForm, \
    UserPermissionForm, GroupPermissionForm


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
        self.devices = AuthServiceApi.get_devices(self.request.COOKIES.get('user_token'), hub)
        return super(HubDeviceView, self).get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super(HubDeviceView, self).get_context_data(**kwargs)
        context['devices'] = self.devices
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


class UpdateDeviceView(HubUserPassesTestMixin, FormView):
    form_class = HubDeviceForm
    template_name = 'MQTTApi/devices/add.html'
    login_url = '/hub/login/'

    def get_context_data(self, **kwargs):
        context = super(UpdateDeviceView, self).get_context_data(**kwargs)
        context['form'] = self.get_form_class()(initial=self.object)
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
                    permission['user'] = group
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
        self.user_permissions = AuthServiceApi.get_device_user_permission(hub['pk'], device['pk'])
        self.group_permissions = AuthServiceApi.get_device_group_permission(hub['pk'], device['pk'])
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
        print("DUPA")
        print(form.errors)
        return super(AddDeviceUserPermissionView, self).form_invalid(form)

    def get_success_url(self):
        return 'dashboard/hub/%s/device/%s/permissions/' % (self.kwargs.get('hub'), self.kwargs.get('device'))
        

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
        self.groups = AuthServiceApi.get_users()
        return super(AddDeviceGroupPermissionView, self).post(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super(AddDeviceGroupPermissionView, self).get_context_data(**kwargs)
        # context['form'] = self.get_form_class()(group_list=self.groups)
        return context

    def form_valid(self, form):
        hub = AuthServiceApi.get_hub(self.kwargs['hub'])
        device_id = int(self.kwargs.get('pk'))
        form.cleaned_data['group'] = int(form.cleaned_data['group'])
        form.cleaned_data['device'] = device_id
        AuthServiceApi.add_device_group_permission(hub, device_id, form.cleaned_data)
        return HttpResponseRedirect(self.get_success_url())

    def get_success_url(self):
        return 'dashboard/hub/%s/device/%s/permissions/' % (self.kwargs.get('hub'), self.kwargs.get('device'))

    def get_form(self, form_class=None):
        if form_class is None:
            form_class = self.get_form_class()
        return form_class(self.groups, **self.get_form_kwargs())
