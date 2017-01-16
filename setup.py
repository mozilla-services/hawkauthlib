#!/usr/bin/env python
# -*- coding: utf-8; mode: python -*-
# pylint: disable=C0103

from os import path
from setuptools import setup, find_packages

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.rst')) as f:
    README = f.read()

with open(path.join(here, 'CHANGES.txt')) as f:
    CHANGES = f.read()

requires       = ['webob']
tests_requires = requires + ['requests']

setup(name='hawkauthlib',
      version                = '2.0.0'
      , description          = 'hawkauth'
      , long_description     = README + '\n\n' + CHANGES
      , license              = 'MPLv2.0'
      , classifiers          = [
          "Programming Language :: Python"
          , "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)" ]
      , author               = 'Mozilla Services'
      , author_email         = 'services-dev@mozilla.org'
      , url                  = 'https://github.com/mozilla-services/hawkauthlib'
      , keywords             = 'authentication Hawk HTTP request signing'
      , packages             = find_packages()
      , include_package_data = True
      , zip_safe             = False
      , install_requires     = requires
      , tests_require        = tests_requires
      , test_suite           = "hawkauthlib"
      , )
