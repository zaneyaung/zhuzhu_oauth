import logging
# from django.conf import settings as django_settings


try:  # Python 2.7+
    from logging import NullHandler
except ImportError:
    class NullHandler(logging.Handler):

        def emit(self, record):
            pass

logging.getLogger('oauthlib').addHandler(NullHandler())
