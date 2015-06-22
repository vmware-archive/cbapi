"""
python-cb-api
"""

from setuptools import setup
import os
import sys

setup(
    name='python-cbapi',
    version='0.5.0',
    url='http://www.carbonblack.com/',
    license='MIT',
    author='Carbon Black',
    author_email='support@carbonblack.com',
    description='CB API Python Bindings',
    long_description=__doc__,
    packages=['cbapi', 'cbapi.util'],
    include_package_data=True,
    package_dir = {'': 'src'},
    zip_safe=False,
    platforms='any',
    classifiers=[
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: MIT',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
