# Generated by Django 2.2.7 on 2019-11-18 15:53

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('AuthService', '0004_auto_20191115_1037'),
    ]

    operations = [
        migrations.RenameField(
            model_name='groupdevicepermission',
            old_name='user',
            new_name='group',
        ),
    ]