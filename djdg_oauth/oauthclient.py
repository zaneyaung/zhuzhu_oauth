# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import json
import requests
from django.conf import settings as django_settings
import re
try:
    from urlparse import urlparse, urlunparse
except ImportError:
    from urllib.parse import urlparse, urlunparse
from .oauthcore import get_verify_key, verifySign, set_parameters, getSign
import logging
from django.http.response import HttpResponse
log_settings = "oauthlib"
if hasattr(django_settings, 'DJDG_AUTH'):
    log_settings = django_settings.DJDG_AUTH.get('log', log_settings)
log = logging.getLogger(log_settings)


class Http401Response(HttpResponse):

    status_code = 401


class OAuthClient(object):
    """
    TODO: add docs
    """
    def __init__(self):
        """
        :params server: An instance of oauthlib.oauth2.Server class
        """
        pass

    def _get_escaped_full_path(self, request):
        """
        Django considers "safe" some characters that aren't so for oauthlib.
        We have to search for them and properly escape.
        """
        parsed = list(urlparse(request.get_full_path()))
        return urlunparse(parsed)

    def _extract_params(self, request):
        """
        """
        uri = self._get_escaped_full_path(request)
        http_method = request.method
        headers = self.extract_headers(request)
        body = self.extract_body(request)
        return uri, http_method, body, headers

    def extract_headers(self, request):
        """
        Extracts headers from the Django request object
        :param request: The current django.http.HttpRequest object
        :return: a dictionary with OAuthLib needed headers
        """
        headers = request.META.copy()
        if 'HTTP_AUTHORIZATION' in headers:
            headers['Authorization'] = headers['HTTP_AUTHORIZATION']
        return headers

    def extract_body(self, request):
        """
        Extracts the POST body from the Django request object
        :param request: The current django.http.HttpRequest object
        :return: provided POST parameters
        """
        if request.environ.get("CONTENT_TYPE") == "application/json;charset=utf-8":
            print "here we are"
            print dir(request)
            print request.body
            print request.POST
            return request.body.decode('utf-8')
        elif request.method == "GET":
            return request.GET.dict()
        else:
            return request.POST.dict()

    def verify_request(self, request):
        """
        :param request: The current django.http.HttpRequest object
        """
        if hasattr(django_settings, "DJDG_AUTH"):
            full_escape_url = django_settings.DJDG_AUTH.get(
                'FULL_ESCAPE_URL', [])
            regex_escape_url = django_settings.DJDG_AUTH.get(
                'REGEX_ESCAPE_URL', [])
            regex_check_url = django_settings.DJDG_AUTH.get(
                'REGEX_CHECK_URL', [])
            path = request.path.strip('/')
            if regex_check_url:
                for url in regex_check_url:
                    if re.match(url, path):
                        break
                else:
                    return
            else:
                if path in full_escape_url:
                    return
                for url in regex_escape_url:
                    if re.match(url, path):
                        return
        uri, http_method, body, headers = self._extract_params(request)
        dict_body = body
        print body
        print type(body)
        if http_method != 'GET':
            dict_body = json.loads(body)
        if not dict_body.get("appid"):
            raise Exception(u"can not find appid in request body")
        keys_obj = get_verify_key(dict_body.get("appid"))
        if not keys_obj:
            raise Exception(
                "can not fetch any settings, please make sure appid incorrect")
        signature = headers.get("Authorization")
        request.client_type = keys_obj.app
        return verifySign(body, keys_obj.secret, signature)

    @staticmethod
    def oauth_request(url, method, app, parameters={}, headers={}):
        secret, parameters = set_parameters(parameters, app)
        # try:
        #     signature, parameters = set_parameters(parameters, app)
        #     print signature
        # except Exception as e:
        #     log.info(e.message)
        #     return {"statusCode": 500, "msg": e.message}
        log.info(parameters)
        res_session = requests.Session()
        if method == "get":
            print "get"
            re = requests.Request(
                method=method, url=url, params=parameters)
        else:
            print "other method"
            headers["Content-Type"] = "application/json;charset=utf-8"
            re = requests.Request(
                method=method, url=url, json=parameters, headers=headers)

        pre_re = res_session.prepare_request(re)
        if method == "get":
            params = parameters
        else:
            params = pre_re.body
        print type(params)
        try:
            signature = getSign(params, secret)
            print signature
        except Exception as e:
            log.info(e.message)
            return {"statusCode": 500, "msg": e.message}
        headers_dict = {
            "Accept": "application/json",
            "Authorization": signature
        }
        headers.update(headers_dict)
        pre_re.prepare_headers(headers)
        print pre_re.headers
        send_kwargs = {
            'timeout': 60,
            'allow_redirects': True,
            "verify": False
        }
        r = res_session.send(pre_re, **send_kwargs)
        print 4
        if r.status_code != 200:
            log.error(r.content)
            return {"statusCode": 500, "msg": r.content}
        else:
                try:
                    log.info(r.json())
                    return {"statusCode": 0, "content": r.json()}
                except:
                    log.info(r.content)
                    return {"statusCode": 0, "content": r.content}
