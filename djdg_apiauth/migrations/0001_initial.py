# -*- coding: utf-8 -*-
# Generated by Django 1.9 on 2016-08-26 06:32
from __future__ import unicode_literals

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django.db.models.manager
import mptt.fields


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='ApiPermission',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=64)),
                ('url', models.CharField(blank=True, max_length=256, null=True)),
                ('http_method', models.CharField(default='GET', max_length=32)),
                ('is_tab', models.BooleanField(default=0)),
                ('url_name', models.CharField(blank=True, max_length=126, null=True, verbose_name='url\u522b\u540d')),
                ('lft', models.PositiveIntegerField(db_index=True, editable=False)),
                ('rght', models.PositiveIntegerField(db_index=True, editable=False)),
                ('tree_id', models.PositiveIntegerField(db_index=True, editable=False)),
                ('level', models.PositiveIntegerField(db_index=True, editable=False)),
                ('parent', mptt.fields.TreeForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='djdg_apiauth.ApiPermission')),
            ],
            options={
                'abstract': False,
            },
            managers=[
                ('tree', django.db.models.manager.Manager()),
            ],
        ),
        migrations.CreateModel(
            name='Group',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=64)),
                ('status', models.BooleanField(default=1)),
                ('api', models.ManyToManyField(blank=True, null=True, to='djdg_apiauth.ApiPermission')),
                ('user', models.ManyToManyField(blank=True, null=True, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
