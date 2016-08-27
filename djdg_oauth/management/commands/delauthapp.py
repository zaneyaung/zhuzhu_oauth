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
            if not auth_keys:
                self.stdout.write(
                    "app {app} auth key not found\n".format(
                        app=app))
                continue
            auth_keys.delete()
            self.stdout.write(
                "app {app} auth key delete success!".format(
                    app=app))
