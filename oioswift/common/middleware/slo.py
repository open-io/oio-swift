import json
from hashlib import md5
from binascii import unhexlify
from swift.common.utils import config_true_value, \
    override_bytes_from_content_type
from swift.common.middleware.slo import filter_factory as slo_filter_factory
from swift.common.middleware.slo import SloGetContext, SloPutContext


OIO_SLO_ETAG_HEADER = "x-object-sysmeta-slo-etag"


def get_or_head_response(self, req, resp_headers, resp_iter):
        segments = self._get_manifest_read(resp_iter)

        etag = md5()
        content_length = 0
        for seg_dict in segments:
            etag.update(unhexlify(seg_dict['hash']))

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


__slo_handle_slo_put = SloPutContext.handle_slo_put


def handle_slo_put(self, req, start_response):
    """
    Modified version of `SloGetContext.handle_slo_put` that computes slo
    etag the same way as Amazon S3 does.
    """
    slo_etag = md5()
    req.body_file.seek(0)
    # Unfortunately the req.body_file that contains the slo manifest has
    # been modified by the calling function. We have to look for 'hash'
    # instead of 'etag'.
    for seg_dict in json.loads(req.body_file.read()):
        slo_etag.update(unhexlify(seg_dict['hash']))
    # This statement will create a system property that we can read
    # during container listing to avoid reading the manifest object.
    req.headers[OIO_SLO_ETAG_HEADER] = slo_etag.hexdigest()
    self.slo_etag = slo_etag
    req.body_file.seek(0)
    return __slo_handle_slo_put(self, req, start_response)


SloGetContext.get_or_head_response = get_or_head_response
SloPutContext.handle_slo_put = handle_slo_put


def filter_factory(global_conf, **local_conf):
    return slo_filter_factory(global_conf, **local_conf)
