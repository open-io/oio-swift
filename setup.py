from setuptools import setup

from oioswift import __version__


setup(
    name='oioswift',
    version=__version__,
    author='OpenIO',
    author_email='support@openio.io',
    description='OpenIO Swift Gateway',
    url='https://github.com/open-io/oio-swift',
    license='Apache License (2.0)',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Programming Language :: Python :: 2.7',
        'License :: OSI Approved :: Apache Software License',
        'Intended Audience :: Information Technology',
        'Operating System :: OS Independent',
    ],
    packages=[
        'oioswift',
        'oioswift.common',
        'oioswift.common.middleware',
        'oioswift.proxy',
        'oioswift.proxy.controllers'],
    entry_points={
        'paste.app_factory': [
            'main=oioswift.server:app_factory',
        ],
        'paste.filter_factory': [
            'autocontainer=oioswift.common.middleware.autocontainer:filter_factory',
            'hashedcontainer=oioswift.common.middleware.hashedcontainer:filter_factory',
            'regexcontainer=oioswift.common.middleware.regexcontainer:filter_factory',
            'versioned_writes=oioswift.common.middleware.versioned_writes:filter_factory',
            'container_hierarchy=oioswift.common.middleware.container_hierarchy:filter_factory',
        ],
    },
    install_requires=['swift>=2.13.0', 'oio>=4.1.0.a0']
)
