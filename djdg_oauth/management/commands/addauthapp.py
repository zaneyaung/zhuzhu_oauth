# -*- coding: utf-8 -*-
from django.core.management.base import BaseCommand
from djdg_oauth.models import OauthApps


class Command(BaseCommand):
    help = 'list, add or delete an app auth'

    def add_arguments(self, parser):
        parser.add_argument('app', nargs='+', type=str)

    def handle(self, *args, **options):
        apps = options["app"]
        for app in apps:
            self.stdout.write("\n=====================\n")
            auth_keys = OauthApps.objects.filter(app=app)
            if auth_keys:
                self.stdout.write(
                    "app {app} auth key already exists,".format(app=app) +
                    " use \'listauthapp\' to check.\n")
                continue
            _auth = OauthApps(app=app)
            _auth.save()
            auth_str = "appid: " + str(_auth.appid) +\
                "\t secret: " + str(_auth.secret)
            self.stdout.write(
                "add app {app} auth key Succeed:\n {auth_str}".format(
                    app=app, auth_str=auth_str))
