#! /usr/bin/env python3
"""
license: MIT, see LICENSE.txt
"""

from setuptools import setup

version = "0.7.0"


entry_points = {"console_scripts": []}

# for more speed/caching (increases performance in some cases e.g. rotating disk)
speed_requirements = ["cachetools>=1.1.0"]
# for server side sorting (only one needed)
# speed_requirements.append("blist>=1.3.6")
speed_requirements.append("sortedcontainers>=1.5.3")

install_requirements = []
# for certificate generation
install_requirements += ["cryptography>=1.1"]
# for pidlock
install_requirements += ["psutil>=3.0"]
# require speed by default
install_requirements += speed_requirements

install_extras = {}
# for markdown help
install_extras["md"] = ["markdown"]
# speed as extra
#install_extras["speed"] = speed_requirements

entry_points["console_scripts"].append('scnmain = simplescn.tools.start:init_method_main')
entry_points["console_scripts"].append('scnconnect = simplescn.cmdcom:init_cmdcom')
#entry_points["console_scripts"].append('scnmassimport = simplescn.massimport:cmdmassimport')

# plugins imported by MANIFEST.in
setup(name='simplescn',
      version=version,
      #version_format='{tag}',
      description='Simple communication nodes',
      author='Alexander K.',
      author_email='devkral@web.de',
      license='MIT',
      url='https://github.com/devkral/simplescn',
      download_url='https://github.com/devkral/simplescn/tarball/'+version,
      entry_points=entry_points,
      #zip_safe=True,
      platforms='Platform Independent',
      include_package_data=True,
      package_data={
          'simplescn': ['*.txt', '*.md'],
      },
      install_requires=install_requirements,
      extras_require=install_extras,
      packages=['simplescn', 'simplescn.client', 'simplescn.cmdcom', 'simplescn.config', 'simplescn.massimport', 'simplescn.pwrequester', 'simplescn.tools'],
      #ext_modules=distributions,
      test_suite="tests",
      classifiers=[
          'License :: OSI Approved :: MIT License',
          'Operating System :: OS Independent',
          'Programming Language :: Python :: 3.5',
          'Programming Language :: Python :: 3 :: Only',
          'Topic :: Communications',
          'Topic :: Internet',
          'Topic :: Security'],
      keywords=['simplescn', 'scn'])
