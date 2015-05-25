from functools import wraps
from hashlib import sha1
import hmac
import json

from django.db import models
from django.db.models.query import QuerySet
from django.conf import settings
from django.core.cache import cache

import logging
logger = logging.getLogger(__name__)

DEFAULT = 60 * 60 * 6 # 6 hours
EXTENDED = 60 * 60 * 24 * 3 # 3 days
FOUND_KEY = 'found_in_cache'
NOT_FOUND_KEY = 'not_found_in_cache'

#######################
### General Methods ###
#######################
def set(key, value, timeout=DEFAULT):
    if not settings.ENABLE_DB_CACHE:
        return
    if isinstance(value, QuerySet): # Can't JSON serialize a QuerySet
        value = list(value)
    try:
        value = json.dumps(value)
    except TypeError as ex:
        logger.warning(
            'json.dumps() for {} failed for reason: {}'.format(key, ex))
    else:
        logger.info("Cache is set for key: %s" % key)
        return cache.set(key, value, timeout=timeout)

def get(key):
    if not settings.ENABLE_DB_CACHE:
        return
    value = cache.get(key)
    track_cache(value)
    if value:
        logger.info("Cache retrieved for key: %s" % key)
    else:
        logger.info("Cache retrieval failed for key: %s" % key)

    return json.loads(value) if value else value

def delete(key):
    if not settings.ENABLE_DB_CACHE:
        return
    logger.info("Cache is deleted for key: %s" % key)
    return cache.delete(key)

def clear():
    logger.info("Cache cleared")
    return cache.clear()

### Internal Monitoring ###
def track_cache(value):
    key = NOT_FOUND_KEY if value is None else FOUND_KEY
    try:
        cache.incr(key)
    except ValueError:
        cache.set(key, 1, timeout=None)

def found():
    return cache.get(FOUND_KEY)

def not_found():
    return cache.get(NOT_FOUND_KEY)

##########################
### Function Decorator ###
##########################
def auto_set(key_template=None, key_params=None, timeout=DEFAULT, is_update=False, set_false=True):
    '''Will cache a function using a key defined in the arguments.

    Example: (key_template='info_{}', key_params=(0, 'id'))
    This will result in a cache key like 'info_394', with member.id = 394

    Arguments:
    key_template -- str, with {} to represent dynamic portions of key.
    key_params -- list of tuples. The first element in the tuple can be either
        an integer or a string. If an integer, it refers to the position of
        a positional argument being passed to the function being
        wrapped. If a string, it refers to the name of a keyword argument.
        Additional elements of the tuple are attributes to be called on that
        argument.
        For instance: [(0, 'id'), ('work','company','id')]

    Keyword Arguments:
    is_update -- bool, will update value in cache for the key (default False)
    set_false -- bool, will not cache if return value is False (default True)
    '''
    def function_wrapper(f):
        @wraps(f)
        def wrapped_function(*args, **kwargs):
            cache_key = create_key(key_template or f.__name__, key_params, locals())
            if is_update:
                delete(cache_key)
            data = None if is_update else get(cache_key)
            if data is None:
                data = f(*args, **kwargs)
                if data or set_false:
                    set(cache_key, data, timeout)
            return data
        return wrapped_function
    return function_wrapper


def create_key(key_template, key_params, local_vars):
    '''Create the cache key by combining the key template with local variables.

    Ex: key_template = 'info_{}_{}'
        key_params = [(0, 'id'), ('do_reduc',)]
        local_vars = {'args':[member], 'kwargs': {'do_reduc': True}}
    '''
    args = local_vars['args']
    kwargs = local_vars['kwargs']
    key_params = key_params or []
    if not isinstance(key_params, list):
        key_params = [key_params]
    key_args = []
    if key_params:
        for p in key_params:
            key_arg = args[p[0]] if isinstance(p[0], int) else kwargs[p[0]]
            for attr in p[1:]: # Additional elements are attributes of arg
                if hasattr(key_arg, attr):
                    key_arg = getattr(key_arg, attr)
                else:
                    # it's possible that key_arg is None
                    key_arg = "default"
            key_args.append(key_arg)
        try:
            cache_key = key_template.format(*key_args)
            return cache_key
        except IndexError as ex:
            logger.info("Cache key creation failed for {}".format(key_template))
            raise ex
    else:
        cache_key = key_template
        for a in args:
            a = a.__class__ if isinstance(a, models.Manager) else a
            cache_key = cache_key + str(a)
        for k in kwargs:
            cache_key = cache_key + str(kwargs[k])
        cache_key = generate_hash(cache_key)
        return cache_key

def generate_hash(base=None):
    base = base or uuid.uuid4().bytes
    return hmac.new(base, digestmod=sha1).hexdigest()
