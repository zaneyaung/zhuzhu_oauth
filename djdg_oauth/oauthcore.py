# -*- coding: utf-8 -*-
from django.conf import settings as django_settings
import random
import hashlib
from .models import OauthApps
import urlparse
import sys
PY3 = sys.version_info[0] == 3

if PY3:
    unicode_type = str
    bytes_type = bytes
else:
    unicode_type = unicode
    bytes_type = str


def createNoncestr(length=32):
    """产生随机字符串，不长于32位"""
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    strs = []
    for x in range(length):
        strs.append(chars[random.randrange(0, len(chars))])
    return "".join(strs)


def formatBizQueryParaMap(paraMap, urlencode):
    """格式化参数，签名过程需要使用"""
    if isinstance(paraMap, (str, unicode)):
        return paraMap
    paraMap = to_unicode(paraMap)
    slist = sorted(paraMap)
    buff = []
    for k in slist:
        v = paraMap[k]
        if v is None or v == "":
            # 为空直接跳过
            continue
        buff.append("{0}={1}".format(k, str(v)))
    return "&".join(buff)


def getSign(obj, secret):
    """生成签名"""
    # 签名步骤一：按字典序排序参数,formatBizQueryParaMap已做
    String = formatBizQueryParaMap(obj, True)
    # 签名步骤二：在string后加入KEY
    String = "{0}&secret={1}".format(String, secret)
    # 签名步骤三：MD5加密
    String = hashlib.md5(String).hexdigest()
    # 签名步骤四：所有字符转为大写
    result_ = String.upper()
    return result_


def verifySign(obj, secret, signature):
    return signature == getSign(obj, secret)


def get_sign_key(app):
    if hasattr(django_settings, "DJDG_AUTH"):
        auth_list = [
            x for x in django_settings.DJDG_AUTH.get(
                "APPS", []) if x["app"] == app]
        return auth_list[0] if auth_list else None
    else:
        return None


def get_verify_key(appid):
    auth_list = OauthApps.objects.filter(appid=appid)
    return auth_list[0] if auth_list else None


def set_parameters(parameters, app):
    appkeys = get_sign_key(app)
    if not appkeys:
        raise Exception("app secret not find, please check you settings file")
    parameters["appid"] = appkeys["appid"]
    parameters["nonce_str"] = createNoncestr(12)
    return appkeys["secret"], parameters


def add_querystr_to_params(url, params):
    """pick url querystring to params"""
    sch, net, path, par, query, fra = urlparse.urlparse(url)
    query_params = urlparse.parse_qsl(query, keep_blank_values=True)
    params.update(query_params)
    uri = urlparse.urlunparse((sch, net, path, par, '', fra))
    return uri, params


def to_unicode(data, encoding='UTF-8'):
    """Convert a number of different types of objects to unicode."""
    import datetime
    import decimal
    type_to_str = (datetime.datetime, decimal.Decimal)
    if hasattr(data, '__iter__'):
        try:
            dict(data)
        except TypeError:
            pass
        except ValueError:
            # Assume it's a one dimensional data structure
            data = [to_unicode(i, encoding) for i in data]
        else:
            # We support 2.6 which lacks dict comprehensions
            if hasattr(data, 'items'):
                data = data.items()
            data = dict([(to_unicode(k, encoding), to_unicode(v, encoding)) for k, v in data])
    if isinstance(data, type_to_str):
        data = str(data)
    if isinstance(data, bytes_type):
        data = unicode(data, encoding='utf-8')
    return data
