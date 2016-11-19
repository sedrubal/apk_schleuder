#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Download latest APKs without Google Play TM."""

from __future__ import print_function

import os
import subprocess

from tabulate import tabulate

from .config import SOURCES, SETTINGS
from .apk_schleuder import APKSchleuder


def print_status(status):
    """Pretty prints the status output by APKSchleuder.get_status"""
    headers = ['name', 'local version', 'source', 'APK file']
    table_data = [
        [name, data['version'], data['source'], data['file']]
        for name, data in status.items()
    ]
    print(tabulate(table_data, headers=headers))


def main():
    """Download specified apps."""
    # create required dirs
    os.makedirs(SETTINGS['repo_dir'], exist_ok=True)
    os.makedirs(SETTINGS['temp_dir'], exist_ok=True)
    # run apk schleuder
    schleuder = APKSchleuder(SOURCES)
    print('Searching for updates...')
    schleuder.update()
    print('Verifying APKs...')
    schleuder.verify()
    # status
    print()
    print_status(schleuder.get_status())
    # update fdroid
    print()
    print('Updating fdroid repo...')
    os.chdir(os.path.join(SETTINGS['repo_dir'], '..'))
    subprocess.call(['fdroid', 'update'])

if __name__ == '__main__':
    main()
