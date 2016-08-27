# -*- coding: utf-8 -*-
import random
# import uuid
UNICODE_ASCII_CHARACTER_SET = ('abcdefghijklmnopqrstuvwxyz'
                               'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
                               '0123456789')
NUMBERIC_ASCII_CHARACTER_SET = ('0123456789')


def gen_app_id():
    return generate_token(8, NUMBERIC_ASCII_CHARACTER_SET)


def gen_secret():
    return generate_token(40, UNICODE_ASCII_CHARACTER_SET)


def gen_sid():
    return generate_token(16, NUMBERIC_ASCII_CHARACTER_SET)


def generate_token(length=30, chars=UNICODE_ASCII_CHARACTER_SET):
    """Generates a non-guessable OAuth token

    OAuth (1 and 2) does not specify the format of tokens except that they
    should be strings of random characters. Tokens should not be guessable
    and entropy when generating the random characters is important. Which is
    why SystemRandom is used instead of the default random.choice method.
    """
    rand = random.SystemRandom()
    return ''.join(rand.choice(chars) for x in range(length))
