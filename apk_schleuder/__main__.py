#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Download latest APKs without Google Play TM."""

from __future__ import print_function

import sys
import os
from distutils.version import StrictVersion
from warnings import warn

from .config import SOURCES, SETTINGS
from .sources_manager import manager_factory

def error(msg):
    """Print a message and exit."""
    print(msg, file=sys.stderr)
    exit(1)


def instantiate_sources():
    """Interates over SOURCES and replaces the config with Manager objects."""
    for app_name, app_managers in SOURCES.items():
        for manager_name, manager_config in app_managers.items():
            manager = manager_factory(manager_config['type'])(
                name=app_name, repo_dir=SETTINGS['repo_dir'],
                **manager_config['config']
            )
            app_managers[manager_name] = manager


def get_latest_versions():
    """
    Return a dict containing the latest versions of apps like this:

    >>> get_latest_version()
    {
        'appname1': {'version': '0.1.2', 'manager_name': 'manager1_name'},
        'appname2': {'version': '1.33.7', 'manager_name': 'manager2_name'},
    }
    """
    results = {}
    for app_name, app_managers in SOURCES.items():
        try:
            app_version, manager_name = max((
                (StrictVersion(m.get_version()), mn)
                for mn, m in app_managers.items()
            ))
            results[app_name] = {
                'version': app_version,
                'manager_name': manager_name,
            }
        except Exception as err:
            warn(str(err))

    return results


def print_versions(app_versions):
    """
    Print the version of all apps.

    app_versions: see result of get_latest_versions
    """
    for app_name, info in app_versions.items():
        print(
            '%s:' % app_name,
            info['version'], '(%s)' % info['manager_name']
        )


def download_apks(app_versions):
    """Download all APKs."""
    for app_name, info in app_versions.items():
        print('%s:' % app_name)
        try:
            print(
                '  - File:',
                SOURCES[app_name][info['manager_name']].get_apk(),
                '(from %s)' % info['manager_name'],
            )
        except Exception as err:
            warn(str(err))


def main():
    """Download specified apps."""
    os.makedirs(SETTINGS['repo_dir'], exist_ok=True)
    os.makedirs(SETTINGS['temp_dir'], exist_ok=True)
    instantiate_sources()
    app_versions = get_latest_versions()
    print_versions(app_versions)
    download_apks(app_versions)

if __name__ == '__main__':
    main()
