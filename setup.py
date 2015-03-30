from setuptools import setup

from oioswift import __version__


setup(
    name='oioswift',
    version=__version__,
    author='OpenIO',
    author_email='support@openio.io',
    description='OpenIO Swift Gateway',
    url='https://github.com/open-io/oio-swift',
    license='AGPLv3',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Programming Language :: Python :: 2.7',
        'License :: OSI Approved :: GNU Affero General Public License v3',
        'Intended Audience :: Information Technology',
        'Operating System :: OS Independent',
    ],
    packages=['oioswift', 'oioswift.controller', 'oioswift.filter'],
    entry_points={
        'paste.app_factory': [
            'main=oioswift.server:app_factory'
        ],
        'paste.filter_factory': [
            'fakeauth=oioswift.filter.fakeauth:filter_factory'
        ]
    },
    install_requires=['WebOb', 'PasteDeploy', 'oiopy']
)