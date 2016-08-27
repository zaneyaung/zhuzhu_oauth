# -*- coding: utf-8 -*-


from rest_framework import serializers
from autho2o.models import Group, ApiPermission


class GroupSerializer(serializers.ModelSerializer):

    class Meta:
        model = Group
        fileds = "__all__"


class ApiPermissionSerializer(serializers.ModelSerializer):

    class Meta:
        model = ApiPermission
        fileds = "__all__"
