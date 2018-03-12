# Configuration

[OpenStack Documentation](https://docs.openstack.org/newton/config-reference/object-storage/proxy-server.html)

## Pipeline

- `catch_errors`
- `proxy-logging`
- `gatekeeper`
- `healthcheck`
- `cache`
- `bulk`: Put before `ratelimit` and your auth filter(s)
    * when misplaced: Nothing
- `tempurl`: Put before `dlo`, `slo` and your auth filter(s)
    * when misplaced: Nothing
- `ratelimit`
- `authtoken`: Put before `s3token`
    * when misplaced: Fail when creating a bucket (`403: SignatureDoesNotMatch`)
- `swift3`: Put before `s3token` or `tempauth`
    * when misplaced: Fail when creating a bucket (`403: SignatureDoesNotMatch`)
- `tempauth`
- `s3token`: Put just before `keystoneauth` and after `swift3`
    * when misplaced: Raise `ValueError: Invalid pipeline`
- `keystoneauth`: Put just after `s3token`
    * when misplaced: If before `s3token`, raise `ValueError: Invalid pipeline`, else nothing    
- `staticweb`: Put just after your auth filter(s)
    * when misplaced: Nothing
- `copy`: Put after your auth filter(s) and before `dlo` and `slo`
    * when misplaced: Nothing
- `container-quotas`: Put after auth filter(s)
    * when misplaced: Nothing
- `account-quotas`: Put after auth filter(s)
    * when misplaced: Nothing
- `slo`: Put after auth filter(s) and `staticweb`
    * when misplaced: Nothing
- `dlo`: Put after auth filter(s) and `staticweb`
    * when misplaced: Nothing
- `container_hierarchy`: Put after `slo`
    * when misplaced: Raise `ValueError: Invalid pipeline`
- `versioned_writes`: Put after `slo` and `dlo`
    * when misplaced: Nothing
- `proxy-server`: Put at the end
    * when misplaced: Raise `LookupError: No section`
