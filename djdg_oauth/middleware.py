# -*- coding: utf-8 -*-
from .oauthclient import OAuthClient, Http401Response


class DjdgAuthMiddleware(object):

    def process_request(self, request):
        try:
            auth = OAuthClient()
            if not auth.verify_request(request):
                return Http401Response('Unauthorized')
        except Exception as e:
            return Http401Response(e.message)
