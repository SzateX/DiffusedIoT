from django.contrib.auth.models import User, Group
from django.db import models
from rest_framework_api_key.models import AbstractAPIKey


class Hub(models.Model):
    name = models.CharField(max_length=200, blank=True)
    private_address = models.GenericIPAddressField()
    public_address = models.GenericIPAddressField()


class HubAPIKey(AbstractAPIKey):
    organization = models.ForeignKey(
        Hub,
        on_delete=models.CASCADE,
        related_name="api_keys",
    )


class RegisteredDevice(models.Model):
    hub = models.ForeignKey(Hub, on_delete=models.CASCADE, related_name="registred_devices")
    device_id = models.IntegerField()


class UserDevicePermission(models.Model):
    device = models.ForeignKey(RegisteredDevice, on_delete=models.CASCADE, related_name="device_user_perms")
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="user_perms")
    read_permission = models.BooleanField()
    write_permission = models.BooleanField()


class GroupDevicePermission(models.Model):
    device = models.ForeignKey(RegisteredDevice, on_delete=models.CASCADE, related_name="device_group_perms")
    group = models.ForeignKey(Group, on_delete=models.CASCADE, related_name="group_perms")
    read_permission = models.BooleanField()
    write_permission = models.BooleanField()