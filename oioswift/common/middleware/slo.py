from hashlib import md5
from swift.common.utils import config_true_value, \
    override_bytes_from_content_type
from swift.common.middleware.slo import filter_factory as slo_filter_factory
from swift.common.middleware.slo import SloGetContext


def get_or_head_response(self, req, resp_headers, resp_iter):
        segments = self._get_manifest_read(resp_iter)

        etag = md5()
        content_length = 0
        for seg_dict in segments:
            if seg_dict.get('range'):
                etag.update('%s:%s;' % (seg_dict['hash'], seg_dict['range']))
            else:
                etag.update(seg_dict['hash'])

            if config_true_value(seg_dict.get('sub_slo')):
                override_bytes_from_content_type(
                    seg_dict, logger=self.slo.logger)
            content_length += self._segment_length(seg_dict)

        response_headers = [(h, v) for h, v in resp_headers
                            if h.lower() not in ('etag', 'content-length')]
        response_headers.append(('Content-Length', str(content_length)))
        response_headers.append(
            ('Etag', '"%s-%d"' % (etag.hexdigest(), len(segments))))

        if req.method == 'HEAD':
            return self._manifest_head_response(req, response_headers)
        else:
            return self._manifest_get_response(
                req, content_length, response_headers, segments)


SloGetContext.get_or_head_response = get_or_head_response

def filter_factory(global_conf, **local_conf):
    return slo_filter_factory(global_conf, **local_conf)
