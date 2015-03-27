import os
from paste.deploy import loadapp
import eventlet
from eventlet import wsgi
import logging.config
config_path = os.environ.get('OIOSWIFT_CONFIG', 'conf/default.cfg')
logging.config.fileConfig("conf/logging.conf")
app = loadapp('config:%s' % config_path, relative_to='.')

wsgi.server(eventlet.listen(('', 5000)), app, None)