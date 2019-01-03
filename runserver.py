import sys
from optparse import OptionParser
from swift.common.utils import parse_options
from swift.common.wsgi import run_wsgi


def run_objgraph(types):
    import objgraph
    import os
    import random
    objgraph.show_most_common_types(limit=50, shortnames=False)
    for type_ in types:
        count = objgraph.count(type_)
        print '%s objects: %d' % (type_, count)
        if count:
            objgraph.show_backrefs(
                random.choice(objgraph.by_type(type_)), max_depth=20,
                filename='/tmp/backrefs_%s_%d.dot' % (type_, os.getpid()))


if __name__ == '__main__':
    parser = OptionParser(usage="%prog CONFIG [options]")
    parser.add_option('--objgraph', action='store_true',
                      help=('Run objgraph, show most common '
                            'types before exiting'))
    parser.add_option('--show-backrefs', action='append', default=list(),
                      help=('Draw backreference graph for one randomly '
                            'chosen object of that type. Can be used '
                            'multiple times.'))
    conf_file, options = parse_options(parser)
    res = run_wsgi(conf_file, 'proxy-server', **options)
    if options.get('objgraph'):
        run_objgraph(options.get('show_backrefs', list()))
    sys.exit(res)
