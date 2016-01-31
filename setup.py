#! /usr/bin/env python3
#license: bsd3, see LICENSE.txt

from setuptools import setup
#, Distribution
#from pkg_resources import Environment, working_set

#import os
#, working_set

#distributions, errors = working_set.find_plugins(Environment("plugins"))
#map(working_set.add, distributions)  # add plugins+libs to sys.path
#if len(errors)>0:
#    print("Error loading plugins: ", errors)
#print(distributions)

# plugins imported by MANIFEST.in
setup(name='simplescn',
      version='0.1',
      description='Simple communication nodes',
      author='Alex',
      author_email='devkral@web.de',
      url='https://github.com/devkral/simplescn',
      scripts=['simplescn.py'],
      #zip_safe=True,
      include_package_data=True,
      package_data={
          'simplescn': ['*.txt', '*.md', 'guigtk/*.ui', 'guigtk/*.svg', 'guigtk/*.py', 'static/*', 'html/*/*.html'],
      },
      install_requires=["cryptography>=1.1"],
      extras_require={
          'gtkgui': ["pygobject"],
      },
      packages=['simplescn'],
      #ext_modules=distributions,
      license="BSD3",
      test_suite="tests")
