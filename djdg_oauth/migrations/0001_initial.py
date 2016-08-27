# -*- coding: utf-8 -*-
# Generated by Django 1.9.2 on 2016-08-24 08:42
from __future__ import unicode_literals

from django.db import migrations, models
import djdg_oauth.generator


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='OauthApps',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('appid', models.CharField(default=djdg_oauth.generator.gen_app_id, max_length=40)),
                ('secret', models.CharField(default=djdg_oauth.generator.gen_secret, max_length=256)),
                ('app', models.CharField(max_length=128)),
            ],
        ),
    ]
