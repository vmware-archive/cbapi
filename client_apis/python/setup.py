"""
python-cb-api
"""

from setuptools import setup
import os
import sys

setup(
    name='cbapi',
    version='0.8.1',
    url='https://github.com/carbonblack/cbapi',
    license='MIT',
    author='Carbon Black',
    author_email='dev-support@carbonblack.com',
    description='CB REST API Python Bindings',
    packages=['cbapi', 'cbapi.util'],
    include_package_data=True,
    package_dir = {'': 'src'},
    zip_safe=False,
    platforms='any',
    install_requires=[
        'simplejson',
        'requests',
        'pika',
        'protobuf'
    ],
    classifiers=[
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
