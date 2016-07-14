#! /usr/bin/env python3
#license: bsd3, see LICENSE.txt

from setuptools import setup


#, Distribution
#from pkg_resources import Environment, working_set


entry_points = {"console_scripts": []}
install_requirements = []
# for certificate generation
install_requirements += ["cryptography>=1.1"]
# for pidlock
install_requirements += ["psutil>=3.0"]

entry_points["console_scripts"].append('scnmain = simplescn.__main__:_init_method_main')
entry_points["console_scripts"].append('scnconnect = simplescn.cmdcom:_init_method_main')
#entry_points["gui_scripts"] += ['simplescngui = simplescn.__main__:client']

# plugins imported by MANIFEST.in
setup(name='simplescn',
      version='0.5.10',
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
      packages=['simplescn', 'simplescn.tools'],
      #ext_modules=distributions,
      license="MIT",
      test_suite="tests")
