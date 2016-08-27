# Create your models here.
# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.db import models

from mptt.fields import TreeForeignKey
from mptt.models import MPTTModel
from django.contrib.auth.models import User
from mptt.managers import TreeManager


class ApiPermission(MPTTModel):
    name = models.CharField(max_length=64)
    url = models.CharField(max_length=256, null=True, blank=True)
    http_method = models.CharField(max_length=32, default='GET')
    is_tab = models.BooleanField(default=0)
    parent = TreeForeignKey('self', null=True, blank=True)
    url_name = models.CharField(
        u"url别名", max_length=126, null=True, blank=True)

    def __unicode__(self):
        return "{0} \t {1} \t {2}".format(self.id, self.url_name, self.name)

    tree = TreeManager()


class Group(models.Model):
    '''
    status: ((0, delete), (1, ok))
    '''
    name = models.CharField(max_length=64)
    status = models.BooleanField(default=1)
    user = models.ManyToManyField(User, null=True, blank=True)
    api = models.ManyToManyField(ApiPermission, null=True, blank=True)

    def __unicode__(self):
        return self.name


# class User_Groups(models.Model):
#     user = models.ForeignKey(User, related_name='autho2o_group')
#     group = models.ForeignKey(Group)

#     def __unicode__(self):
#         return "{} {}".format(self.user.username, self.group.name)


# class Group_ApiPermission(models.Model):
#     group = models.ForeignKey(Group, related_name='api_group')
#     apipermission = models.ForeignKey(ApiPermission)

#     def __unicode__(self):
#         return "{} {}".format(self.group.name, self.apipermission.name)
