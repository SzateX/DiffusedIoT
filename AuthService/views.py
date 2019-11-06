from django.contrib.auth.mixins import UserPassesTestMixin
from django.contrib.auth.views import LoginView, LogoutView
from django.shortcuts import render, get_object_or_404
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm, UserChangeForm

# Create your views here.
from django.views.generic import TemplateView, ListView, CreateView, \
    UpdateView, DeleteView, DetailView

from AuthService.models import Hub, Device, DeviceUnit


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


class HubView(UserPassesTestMixin, DetailView):
    login_url = LOGIN_URL
    permission_denied_message = PERMISSION_DENIED_MESSAGE
    template_name = "AuthService/hubs/hub.html"
    context_object_name = "hub"

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


class DevicesView(UserPassesTestMixin, ListView):
    login_url = LOGIN_URL
    permission_denied_message = PERMISSION_DENIED_MESSAGE
    template_name = "AuthService/devices.html"
    context_object_name = "devices"

    def test_func(self):
        return self.request.user.is_staff

    def get_queryset(self):
        hub = get_object_or_404(Hub, pk=self.kwargs['hub'])
        return Device.objects.filter(hub=hub)


class DeviceUnitsView(UserPassesTestMixin, ListView):
    login_url = LOGIN_URL
    permission_denied_message = PERMISSION_DENIED_MESSAGE
    template_name = "AuthService/units.html"
    context_object_name = "units"

    def test_func(self):
        return self.request.user.is_staff

    def get_queryset(self):
        hub = get_object_or_404(Hub, pk=self.kwargs['hub'])
        device = get_object_or_404(Device, pk=self.kwargs['device'], hub=hub)
        return DeviceUnit.objects.filter(device=device)
