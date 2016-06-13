#! /usr/bin/env python3
#license: bsd3, see LICENSE.txt

from setuptools import setup


#, Distribution
#from pkg_resources import Environment, working_set


entry_points = {"console_scripts": []}
install_requirements = ["cryptography>=1.1"]

entry_points["console_scripts"].append('scnmain = simplescn.__main__:init_method_main')
entry_points["console_scripts"].append('scnconnect = simplescn.cmdcom:init_method_main')
#entry_points["gui_scripts"] += ['simplescngui = simplescn.__main__:client']

# plugins imported by MANIFEST.in
setup(name='simplescn',
      version='0.1.90',
      description='Simple communication nodes',
      author='Alexander K.',
      author_email='devkral@web.de',
      url='https://github.com/devkral/simplescn',
      entry_points=entry_points,
      #zip_safe=True,
      platforms='Platform Independent',
      include_package_data=True,
      package_data={
          'simplescn': ['*.txt', '*.md'],
      },
      install_requires=install_requirements,
      packages=['simplescn'],
      #ext_modules=distributions,
      license="MIT",
      test_suite="tests")
