# Generated by Django 2.2.7 on 2019-12-02 15:34

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('AuthServiceApp', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='hub',
            name='private_address',
            field=models.URLField(),
        ),
        migrations.AlterField(
            model_name='hub',
            name='public_address',
            field=models.URLField(),
        ),
    ]
