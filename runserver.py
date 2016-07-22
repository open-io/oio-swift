import sys
from swift.common.utils import parse_options
from swift.common.wsgi import run_wsgi

if __name__ == '__main__':
    conf_file, options = parse_options()
    sys.exit(run_wsgi(conf_file, 'proxy-server', **options))
