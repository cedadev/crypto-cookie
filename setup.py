#!/usr/bin/env python

"""Distribution Utilities setup program for NDG Security Package

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "24/04/06"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'

# Bootstrap setuptools if necessary.
try:
    from setuptools import setup, find_packages
except ImportError:
    from ez_setup import use_setuptools
    use_setuptools()
    from setuptools import setup, find_packages

import sys
import os

# Packages needed for NDG Security
# Note commented out ones fail with PyPI - use explicit link instead
_PKG_DEPENDENCIES = [
    'ndg-httpsclient',
    'ndg_saml',
    'ndg_xacml'
    ]

# Python 2.5 includes ElementTree by default
if sys.version_info[0:2] < (2, 5):
    _PKG_DEPENDENCIES += ['ElementTree', 'cElementTree']

THIS_DIR = os.path.dirname(__file__)
try:
    LONG_DESCR = open(os.path.join(THIS_DIR, 'README.md')).read()
except IOError:
    LONG_DESCR = ""

setup(
    name =                   'crypto-cookie',
    version =                '0.1.0',
    description =            'Package to encrypt and sign cookies',
    long_description =       LONG_DESCR,
    author =                 'Philip Kershaw',
    author_email =           'Philip.Kershaw@stfc.ac.uk',
    maintainer =             'Philip Kershaw',
    maintainer_email =       'Philip.Kershaw@stfc.ac.uk',
    url =                    'https://github.com/cedadev/crypto-cookie',
    license =                'BSD - See LICENCE file for details',
    install_requires =        [],
    dependency_links =        ["http://dist.ceda.ac.uk/pip/"],
    packages =               find_packages(),
    entry_points =         None,
    test_suite =           'ndg.security.common.test',
    zip_safe =             False
)
