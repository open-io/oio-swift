
from swift.common.utils import get_logger
from swift.common.swob import Request

class ServerSideCopyMiddleware(object):
    def __init__(self, app, conf):
        self.app = app
        self.logger = get_logger(conf, log_route="copy")

    def __call__(self, env, start_response):
        req = Request(env)
        try:
            (version, account, container, obj) = req.split_path(4, 4, True)
        except ValueError:
            # If obj component is not present in req, do not proceed further.
            return self.app(env, start_response)

        self.account_name = account
        self.container_name = container
        self.object_name = obj

        """ TODO explore various case shown below !
        try:
            # In some cases, save off original request method since it gets
            # mutated into PUT during handling. This way logging can display
            # the method the client actually sent.
            if req.method == 'PUT' and req.headers.get('X-Copy-From'):
                return self.handle_PUT(req, start_response)
            elif req.method == 'COPY':
                req.environ['swift.orig_req_method'] = req.method
                return self.handle_COPY(req, start_response)
            elif req.method == 'POST' and self.object_post_as_copy:
                req.environ['swift.orig_req_method'] = req.method
                return self.handle_object_post_as_copy(req, start_response)
            elif req.method == 'OPTIONS':
                # Does not interfere with OPTIONS response from
                # (account,container) servers and /info response.
                return self.handle_OPTIONS(req, start_response)

        except HTTPException as e:
            return e(req.environ, start_response)
        """

        return self.app(env, start_response)

def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def copy_filter(app):
        return ServerSideCopyMiddleware(app, conf)

    return copy_filter
