# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models
from .generator import gen_app_id, gen_secret

# Create your models here.


class OauthApps(models.Model):
    """
    appliction's secret and app key list
    """
    appid = models.CharField(max_length=40, default=gen_app_id)
    secret = models.CharField(max_length=256, default=gen_secret)
    app = models.CharField(max_length=128)

    def __str__(self):
        return self.app
