# Generated by Django 2.2.7 on 2019-12-02 14:27

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('auth', '0011_update_proxy_permissions'),
    ]

    operations = [
        migrations.CreateModel(
            name='Hub',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(blank=True, max_length=200)),
                ('private_address', models.GenericIPAddressField()),
                ('public_address', models.GenericIPAddressField()),
            ],
        ),
        migrations.CreateModel(
            name='RegisteredDevice',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('device_id', models.IntegerField()),
                ('hub', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='registred_devices', to='AuthServiceApp.Hub')),
            ],
        ),
        migrations.CreateModel(
            name='UserDevicePermission',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('read_permission', models.BooleanField()),
                ('write_permission', models.BooleanField()),
                ('device', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='device_user_perms', to='AuthServiceApp.RegisteredDevice')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='user_perms', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='HubAPIKey',
            fields=[
                ('id', models.CharField(editable=False, max_length=100, primary_key=True, serialize=False, unique=True)),
                ('prefix', models.CharField(editable=False, max_length=8, unique=True)),
                ('hashed_key', models.CharField(editable=False, max_length=100)),
                ('created', models.DateTimeField(auto_now_add=True, db_index=True)),
                ('name', models.CharField(default=None, help_text='A free-form name for the API key. Need not be unique. 50 characters max.', max_length=50)),
                ('revoked', models.BooleanField(blank=True, default=False, help_text='If the API key is revoked, clients cannot use it anymore. (This cannot be undone.)')),
                ('expiry_date', models.DateTimeField(blank=True, help_text='Once API key expires, clients cannot use it anymore.', null=True, verbose_name='Expires')),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='api_keys', to='AuthServiceApp.Hub')),
            ],
            options={
                'verbose_name': 'API key',
                'verbose_name_plural': 'API keys',
                'ordering': ('-created',),
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='GroupDevicePermission',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('read_permission', models.BooleanField()),
                ('write_permission', models.BooleanField()),
                ('device', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='device_group_perms', to='AuthServiceApp.RegisteredDevice')),
                ('group', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='group_perms', to='auth.Group')),
            ],
        ),
    ]
