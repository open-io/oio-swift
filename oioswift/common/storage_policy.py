from swift.common import storage_policy

default_policies = [
    storage_policy.StoragePolicy(0, 'Policy-0', True)
]

POLICIES = storage_policy.StoragePolicyCollection(default_policies)
