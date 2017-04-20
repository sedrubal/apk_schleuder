#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

"""Setup script."""

import os
import io

from setuptools import find_packages
from setuptools import setup


def read(*names, **kwargs):
    """open a file and read it's content"""
    return io.open(
        os.path.join(os.path.dirname(__file__), *names),
        encoding=kwargs.get('encoding', 'utf8')
    ).read()


def get_requirements(filename="requirements.txt"):
    """returns a list of all requirements"""
    text = read(filename)
    requirements = []
    for line in text.splitlines():
        req = line.split('#')[0].strip()
        if req != '':
            requirements.append(req)
    return requirements


setup(
    name='apk_schleuder',
    license='MIT',
    description='Download apks from shady sources and put them into a f-droid repo.',
    long_description=read('README.md'),
    author='sedrubal',
    author_email='dev@sedrubal.de',
    url='https://github.com/sedrubal/apk_schleuder',
    packages=find_packages(),
    classifiers=[
        # classifiers: http://pypi.python.org/pypi?%3Aaction=list_classifiers
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: Unix',
        'Operating System :: POSIX',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Topic :: System :: Software Distribution',
    ],
    keywords=[
        'script', 'apktool', 'google-play', 'fdroid', 'android',
    ],
    install_requires=get_requirements(),
    extras_require={
        # eg:
        #   'rst': ['docutils>=0.11'],
        #   ':python_version=="2.6"': ['argparse'],
        'production': ['jarsigner', 'keytool'],
    },
)
