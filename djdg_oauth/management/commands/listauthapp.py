# -*- coding: utf-8 -*-
from django.core.management.base import BaseCommand
from djdg_oauth.models import OauthApps


class Command(BaseCommand):
    help = 'list, add or delete an app auth'

    def add_arguments(self, parser):
        parser.add_argument('app', nargs='+', type=str)
        # parser.add_argument(
        #     '--l',
        #     dest='list',
        #     default='list',
        #     type=str,
        #     help='List secret info of the input app ',
        # )
        # parser.add_argument(
        #     '--a',
        #     dest='add',
        #     default='add',
        #     type=str,
        #     help='add secret info of the input app ',
        # )
        # parser.add_argument(
        #     '--d',
        #     dest='delete',
        #     default='delete',
        #     type=str,
        #     help='delete secret info of the input app ',
        # )

    def handle(self, *args, **options):
        apps = options["app"]
        for app in apps:
            self.stdout.write("=====================\n")
            auth_keys = OauthApps.objects.filter(app=app)
            if not auth_keys:
                self.stdout.write(
                    "app {app} auth key not found\n".format(
                        app=app),)
                continue
            else:
                auth_key = auth_keys[0]
                auth_str = "appid: " + str(auth_key.appid) +\
                    "\t secret: " + str(auth_key.secret)
                self.stdout.write("app {app} auth key:\n {auth_str}\n".format(
                    app=app, auth_str=auth_str),)
