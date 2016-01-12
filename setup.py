#! /usr/bin/env python3

from setuptools import setup, Distribution
#from pkg_resources import Environment, working_set

#import os
#, working_set

#distributions, errors = working_set.find_plugins(Environment("plugins"))
#map(working_set.add, distributions)  # add plugins+libs to sys.path
#if len(errors)>0:
#    print("Error loading plugins: ", errors)
#print(distributions)

setup(name='simplescn',
    version='0.1',
    description='Simple communication nodes',
    author='Alex',
    author_email='devkral@web.de',
    url='https://github.com/devkral/simplescn',
    scripts = ['simplescn/client.py', 'simplescn/guiclient.py', 'simplescn/server.py'],
    include_package_data=True,
    package_data={
        'simplescn': ['guigtk/*.ui', 'guigtk/*.svg', 'guigtk/*.py', 'static/*', 'html/*/*.html'],
    },
    install_requires=["cryptography>=1.1"],
    extras_require = {
        'gtkgui':  ["pygobject"],
    },
    #entry_points= {
    #"setuptools.file_finders": [
    #    "simplescn.plugins = my_foobar_module:find_files_for_foobar"
    #]
    #},
    #entry_points="""
    #      [console_scripts]
    #      scnclient_nogui = simplescn.client:main
    #      scnserver = simplescn.server:main
    #      scnclient = simplescn.guiclient:main
    #  """,
    packages=['simplescn'],
    #ext_modules=distributions,
    license="BSD",
    test_suite="tests"
    
     )
