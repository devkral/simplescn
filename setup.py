#! /usr/bin/env python3

from setuptools import setup, find_packages

setup(name='simplescn',
      version='0.1',
      description='Simple communication nodes',
      author='Alex',
      author_email='devkral@web.de',
      url='https://github.com/devkral/simplescn',
      scripts = ['client.py', 'guiclient.py', 'server.py'],
      license = "BSD3",
      test_suite = "tests"
      
     )
