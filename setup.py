#! /usr/bin/env python3
"""
license: MIT, see LICENSE.txt
"""

from setuptools import setup

version = "0.6.1"


entry_points = {"console_scripts": []}
install_requirements = []
# for certificate generation
install_requirements += ["cryptography>=1.1"]
# for pidlock
install_requirements += ["psutil>=3.0"]
# for caching (increases performance in some cases e.g. rotating disk)
install_requirements += ["cachetools>=1.1.0"]

entry_points["console_scripts"].append('scnmain = simplescn.__main__:_init_method_main')
entry_points["console_scripts"].append('scnconnect = simplescn.cmdcom:_init_method_main')
#entry_points["gui_scripts"] += ['simplescngui = simplescn.__main__:client']

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
      packages=['simplescn', 'simplescn.tools'],
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
