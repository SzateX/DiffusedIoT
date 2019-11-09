from django.contrib.auth.mixins import UserPassesTestMixin
from django.contrib.auth.views import LoginView, LogoutView
from django.http import HttpResponseRedirect
from django.shortcuts import render, get_object_or_404
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm, UserChangeForm

# Create your views here.
from django.views.generic import TemplateView, ListView, CreateView, \
    UpdateView, DeleteView, DetailView, RedirectView

from AuthService.models import Hub, HubAPIKey

LOGIN_URL = '/dashboard/login'
PERMISSION_DENIED_MESSAGE = 'Sorry, you need to have admin, to see this site.'


class UserLoginView(LoginView):
    success_url = "/authService/dashboard"


class UserLogoutView(LogoutView):
    next_page = "/authService/dashboard"


class DashboardView(UserPassesTestMixin, TemplateView):
    template_name = "AuthService/dashboard.html"
    login_url = LOGIN_URL
    permission_denied_message = PERMISSION_DENIED_MESSAGE

    def test_func(self):
        return self.request.user.is_staff


class UsersView(UserPassesTestMixin, ListView):
    login_url = LOGIN_URL
    permission_denied_message = PERMISSION_DENIED_MESSAGE
    template_name = "AuthService/users.html"
    context_object_name = "users"
    queryset = User.objects.all().exclude(username="AnonymousUser")

    def test_func(self):
        return self.request.user.is_staff


class UserView(UserPassesTestMixin, DetailView):
    login_url = LOGIN_URL
    permission_denied_message = PERMISSION_DENIED_MESSAGE
    template_name = "AuthService/users/detail.html"
    model = User
    context_object_name = 'user'

    def test_func(self):
        return self.request.user.is_staff


class UserCreateView(UserPassesTestMixin, CreateView):
    login_url = LOGIN_URL
    permission_denied_message = PERMISSION_DENIED_MESSAGE
    form_class = UserCreationForm
    template_name = "AuthService/users/create.html"
    success_url = "/authService/dashboard/users"

    def test_func(self):
        return self.request.user.is_staff


class UserUpdateView(UserPassesTestMixin, UpdateView):
    login_url = LOGIN_URL
    permission_denied_message = PERMISSION_DENIED_MESSAGE
    form_class = UserChangeForm
    model = User
    template_name = "AuthService/users/update.html"
    success_url = "/authService/dashboard/users"

    def test_func(self):
        return self.request.user.is_staff


class UserDeleteView(UserPassesTestMixin, DeleteView):
    login_url = LOGIN_URL
    permission_denied_message = PERMISSION_DENIED_MESSAGE
    template_name = "AuthService/users/delete.html"
    model = User
    success_url = "/authService/dashboard/users"

    def test_func(self):
        return self.request.user.is_staff


class HubsView(UserPassesTestMixin, ListView):
    login_url = LOGIN_URL
    permission_denied_message = PERMISSION_DENIED_MESSAGE
    template_name = "AuthService/hubs.html"
    context_object_name = "hubs"
    model = Hub

    def test_func(self):
        return self.request.user.is_staff

    def get_context_data(self, *, object_list=None, **kwargs):
        context = super(HubsView, self).get_context_data(**kwargs)
        key = self.request.GET.get('key', None)
        if key:
            context['api_key'] = key
        context['has_api_key'] = key is not None
        return context

class HubView(UserPassesTestMixin, DetailView):
    login_url = LOGIN_URL
    permission_denied_message = PERMISSION_DENIED_MESSAGE
    template_name = "AuthService/hubs/detail.html"
    context_object_name = "hub"
    model = Hub

    def test_func(self):
        return self.request.user.is_staff


class HubCreateView(UserPassesTestMixin, CreateView):
    login_url = LOGIN_URL
    permission_denied_message = PERMISSION_DENIED_MESSAGE
    template_name = "AuthService/hubs/create.html"
    model = Hub
    success_url = "/authService/dashboard/hubs"
    fields = ['name', 'private_address', 'public_address']

    def test_func(self):
        return self.request.user.is_staff

    def form_valid(self, form):
        self.object = form.save()
        api_key, key = HubAPIKey.objects.create_key(name=self.object.name, organization=self.object)
        return HttpResponseRedirect(self.get_success_url() + "?key=" + key)


class HubUpdateView(UserPassesTestMixin, UpdateView):
    login_url = LOGIN_URL
    permission_denied_message = PERMISSION_DENIED_MESSAGE
    template_name = "AuthService/hubs/update.html"
    model = Hub
    success_url = "/authService/dashboard/hubs"
    fields = ['name', 'private_address', 'public_address']

    def test_func(self):
        return self.request.user.is_staff


class HubDeleteView(UserPassesTestMixin, DeleteView):
    login_url = LOGIN_URL
    permission_denied_message = PERMISSION_DENIED_MESSAGE
    template_name = "AuthService/hubs/delete.html"
    model = Hub
    success_url = "/authService/dashboard/hubs"

    def test_func(self):
        return self.request.user.is_staff


class HubResetApiKey(UserPassesTestMixin, RedirectView):
    login_url = LOGIN_URL
    permission_denied_message = PERMISSION_DENIED_MESSAGE
    pattern_name = 'hubs'

    def test_func(self):
        return self.request.user.is_staff

    def get_redirect_url(self, *args, **kwargs):
        kwargs.pop('hub', None)
        url = super(HubResetApiKey, self).get_redirect_url(*args, **kwargs)
        hub = get_object_or_404(Hub, pk=self.kwargs['hub'])
        keys = HubAPIKey.objects.filter(organization=hub, revoked=False)
        for key in keys:
            key.revoked = True
            key.save()
        api_key, key = HubAPIKey.objects.create_key(name=hub.name, organization=hub)
        return url + "?key=" + key


# class DevicesView(UserPassesTestMixin, ListView):
#     login_url = LOGIN_URL
#     permission_denied_message = PERMISSION_DENIED_MESSAGE
#     template_name = "AuthService/devices.html"
#     context_object_name = "devices"
#
#     def test_func(self):
#         return self.request.user.is_staff
#
#     def get_queryset(self):
#         hub = get_object_or_404(Hub, pk=self.kwargs['hub'])
#         return Device.objects.filter(hub=hub)
#
#
# class DeviceUnitsView(UserPassesTestMixin, ListView):
#     login_url = LOGIN_URL
#     permission_denied_message = PERMISSION_DENIED_MESSAGE
#     template_name = "AuthService/units.html"
#     context_object_name = "units"
#
#     def test_func(self):
#         return self.request.user.is_staff
#
#     def get_queryset(self):
#         hub = get_object_or_404(Hub, pk=self.kwargs['hub'])
#         device = get_object_or_404(Device, pk=self.kwargs['device'], hub=hub)
#         return DeviceUnit.objects.filter(device=device)
