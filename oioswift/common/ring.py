import time
from swift.common.ring import Ring


class FakeRing(Ring):
    def __init__(self, replicas=3, max_more_nodes=0, part_power=0,
                 base_port=1000, ring_name=None):
        self.ring_name = ring_name
        self._base_port = base_port
        self.max_more_nodes = max_more_nodes
        self._part_shift = 32 - part_power
        self.set_replicas(replicas)
        self._reload()

    def _reload(self):
        self._rtime = time.time()

    def set_replicas(self, replicas):
        self.replicas = replicas
        self._devs = []
        for x in range(self.replicas):
            ip = '10.0.0.%s' % x
            port = self._base_port + x
            self._devs.append({
                'ip': ip,
                'replication_ip': ip,
                'port': port,
                'replication_port': port,
                'device': 'sd' + (chr(ord('a') + x)),
                'zone': x % 3,
                'region': x % 2,
                'id': x,
            })

    @property
    def replica_count(self):
        return self.replicas

    def _get_part_nodes(self, part):
        return [dict(node, index=i) for i, node in enumerate(list(self._devs))]

    def get_more_nodes(self, part):
        for x in range(self.replicas, (self.replicas + self.max_more_nodes)):
            yield {'ip': '10.0.0.%s' % x,
                   'replication_ip': '10.0.0.%s' % x,
                   'port': self._base_port + x,
                   'replication_port': self._base_port + x,
                   'device': 'sda',
                   'zone': x % 3,
                   'region': x % 2,
                   'id': x}
