from __future__ import print_function
import sys
import logging
from collections import defaultdict
from contextlib import contextmanager
from mock import MagicMock as Mock
from swift.common import utils
from swift.common.utils import NOTICE
from oio.api.object_storage import ObjectStorageApi
from oio.account.client import AccountClient
from oio.container.client import ContainerClient
from oio.blob.client import BlobClient


class FakeMemcache(object):
    def __init__(self):
        self.store = {}

    def get(self, key):
        return self.store.get(key)

    def keys(self):
        return self.store.keys()

    def set(self, key, value, time=0):
        self.store[key] = value
        return True

    def incr(self, key, time=0):
        self.store[key] = self.store.setdefault(key, 0) + 1
        return self.store[key]

    @contextmanager
    def soft_lock(self, key, timeout=0, retries=5):
        yield True

    def delete(self, key):
        try:
            del self.store[key]
        except Exception:
            pass
        return True


class FakeStorageAPI(ObjectStorageApi):
    def __init__(self, *args, **kwargs):
        self.account = Mock(AccountClient)
        self.container = Mock(ContainerClient, perfdata=None)
        self.__dict__.update(kwargs)
        self._blob_client = Mock(BlobClient)
        self._global_kwargs = dict()


class DebugLogAdapter(utils.LogAdapter):

    def _send_to_logger(name):
        def stub_fn(self, *args, **kwargs):
            return getattr(self.logger, name)(*args, **kwargs)
        return stub_fn

    def __getattribute__(self, name):
        try:
            return object.__getattribute__(self, name)
        except AttributeError:
            return getattr(self.__dict__['logger'], name)


def debug_logger(name):
    return DebugLogAdapter(DebugLogger(), name)


class FakeLogger(logging.Logger, object):
    def __init__(self, *args, **kwargs):
        self._clear()
        self.name = 'swift.unit.fake_logger'
        self.level = logging.NOTSET
        if 'facility' in kwargs:
            self.facility = kwargs['facility']
        self.statsd_client = None
        self.threads_locals = None
        self.parent = None

    store_in = {
        logging.ERROR: 'error',
        logging.WARNING: 'warning',
        logging.INFO: 'info',
        logging.DEBUG: 'debug',
        logging.CRITICAL: 'critical',
        NOTICE: 'notice',
    }

    def notice(self, msg, *args, **kwargs):
        self.log(NOTICE, msg, *args, **kwargs)

    def _log(self, level, msg, *args, **kwargs):
        store_name = self.store_in[level]
        cargs = [msg]
        if any(args):
            cargs.extend(args)
        captured = dict(kwargs)
        if 'exc_info' in kwargs and \
                not isinstance(kwargs['exc_info'], tuple):
            captured['exc_info'] = sys.exc_info()
        self.log_dict[store_name].append((tuple(cargs), captured))
        super(FakeLogger, self)._log(level, msg, *args, **kwargs)

    def _clear(self):
        self.log_dict = defaultdict(list)
        self.lines_dict = {'critical': [], 'error': [], 'info': [],
                           'warning': [], 'debug': [], 'notice': []}

    clear = _clear

    def get_lines_for_level(self, level):
        if level not in self.lines_dict:
            raise KeyError(
                "Invalid log level '%s'; valid levels are %s" %
                (level,
                 ', '.join("'%s'" % lvl for lvl in sorted(self.lines_dict))))
        return self.lines_dict[level]

    def all_log_lines(self):
        return dict((level, msgs) for level, msgs in self.lines_dict.items()
                    if len(msgs) > 0)

    def _store_in(store_name):
        def stub_fn(self, *args, **kwargs):
            self.log_dict[store_name].append((args, kwargs))
        return stub_fn

    update_stats = _store_in('update_stats')
    increment = _store_in('increment')
    decrement = _store_in('decrement')
    timing = _store_in('timing')
    timing_since = _store_in('timing_since')
    transfer_rate = _store_in('transfer_rate')
    set_statsd_prefix = _store_in('set_statsd_prefix')

    def get_increments(self):
        return [call[0][0] for call in self.log_dict['increment']]

    def get_increment_counts(self):
        counts = {}
        for metric in self.get_increments():
            if metric not in counts:
                counts[metric] = 0
            counts[metric] += 1
        return counts

    def setFormatter(self, obj):
        self.formatter = obj

    def close(self):
        self._clear()

    def set_name(self, name):
        self._name = name

    def acquire(self):
        pass

    def release(self):
        pass

    def createLock(self):
        pass

    def emit(self, record):
        pass

    def _handle(self, record):
        try:
            line = record.getMessage()
        except TypeError:
            print('WARNING: unable to format log message %r %% %r' % (
                record.msg, record.args))
            raise
        self.lines_dict[record.levelname.lower()].append(line)

    def handle(self, record):
        self._handle(record)

    def flush(self):
        pass

    def handleError(self, record):
        pass


class DebugSwiftLogFormatter(utils.SwiftLogFormatter):
    def format(self, record):
        msg = super(DebugSwiftLogFormatter, self).format(record)
        return msg.replace('#012', '\n')


class DebugLogger(FakeLogger):
    def __init__(self, *args, **kwargs):
        FakeLogger.__init__(self, *args, **kwargs)
        self.formatter = DebugSwiftLogFormatter(
            "%(server)s %(levelname)s: %(message)s")

    def handle(self, record):
        self._handle(record)
        print(self.formatter.format(record))
