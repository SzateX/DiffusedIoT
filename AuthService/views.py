from django.contrib.auth.mixins import UserPassesTestMixin
from django.contrib.auth.views import LoginView, LogoutView
from django.shortcuts import render


# Create your views here.
from django.views.generic import TemplateView


class UserLoginView(LoginView):
    success_url = "/"


class UserLogoutView(LogoutView):
    next_page = "/"


class DashboardView(UserPassesTestMixin, TemplateView):
    template_name = "AuthService/dashboard.html"

    def test_func(self):
        return self.request.user.is_staff

