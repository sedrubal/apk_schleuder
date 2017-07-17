# -*- coding: utf-8 -*-
"""Main APKSchleuder module."""

import json
import logging
import os
from collections import namedtuple
from distutils.version import LooseVersion
from operator import attrgetter

from .config import SETTINGS
from .sources_manager import manager_factory
from .utils import remove_file


class APKSchleuder(object):
    """Core of APK Schleuder."""

    def __init__(self, config_sources):
        """Read config and create sources."""
        self.sources = {}
        for app_name, app_managers in config_sources.items():
            self.sources[app_name] = {}
            for manager_name, manager_config in app_managers.items():
                try:
                    manager = manager_factory(manager_config['type'])(
                        name=app_name, **manager_config
                    )
                except TypeError as exc:
                    print(
                        '[!] Invalid Config for manager {0} for app {1}:'
                        .format(manager_name, app_name)
                    )
                    print(exc)
                    exit(1)

                self.sources[app_name][manager_name] = manager

    @staticmethod
    def sort_managers_by_version(app_managers, app_name):
        """
        Return a list of managers sorted by their latest version and priority.

        >>> get_latest_version()
        [
            ('1.33.7', 1, 'manager_name1'),
            ('1.33.7', 0, 'manager_name2'),
            ('1.33.6', 0, 'manager_name3'),
        ]
        """
        VersionManagerTuple = namedtuple(
            'VersionManagerTuple', ['version', 'priority', 'manager_name']
        )
        version_manager_tuples = []
        for manager_name, manager in app_managers.items():
            try:
                manager_version = LooseVersion(manager.version)
                manager_version.parse  # NOQA: test if version is ok
                version_manager_tuples.append(
                    VersionManagerTuple(
                        version=manager_version,
                        priority=manager.priority,
                        manager_name=manager_name,
                    )
                )
            except Exception as exc:  # NOQA
                logging.warning(
                    'Ignoring manager %r for app %r due to error:',
                    manager_name, app_name
                )
                logging.warning('%s: %s', exc.__class__.__name__, str(exc))

        return sorted(
            version_manager_tuples,
            reverse=True,
            key=attrgetter('version', 'priority'),
        )

    def _get_db(self):
        """Open, read and update the db json."""
        try:
            with open(SETTINGS['db_file'], 'r') as db_file:
                db_json = json.load(db_file)

        except (FileNotFoundError, json.decoder.JSONDecodeError):
            db_json = {}

        def _validate_version(cfg_app):
            try:
                return LooseVersion(cfg_app.get('version', '0.0.0'))
            except ValueError:
                return LooseVersion('0.0.0')

        def _validate_file(cfg_app):
            if not cfg_app.get('file') or not os.path.isfile(cfg_app['file']):
                return None
            else:
                return cfg_app['file']

        for app_name in self.sources:
            if app_name not in db_json:
                db_json[app_name] = {}

            db_json[app_name]['version'] = _validate_version(db_json[app_name])
            db_json[app_name]['file'] = _validate_file(db_json[app_name])

        return db_json

    def _write_db(self, data):
        """Write the db to json file."""
        # preserialize
        for app_data in data.values():
            app_data['version'] = str(app_data['version'])

        db_file = open(SETTINGS['db_file'], 'w')
        json.dump(data, db_file, indent='  ', sort_keys=True)

    def update(self):
        """Update local APKs if needed."""
        db_json = self._get_db()

        for app_name, app_managers in self.sources.items():
            version_sorted_manager_tuples = APKSchleuder.sort_managers_by_version(
                app_managers, app_name
            )
            if not version_sorted_manager_tuples:
                continue  # update failed

            local_version = db_json[app_name]['version']
            for remote_version, _, manager_name in version_sorted_manager_tuples:
                if local_version >= remote_version and db_json[app_name]['file']:
                    break  # no update found and local file is present

                manager = self.sources[app_name][manager_name]
                print(
                    'Updating',
                    app_name,
                    'from',
                    local_version,
                    'to',
                    remote_version,
                    'using',
                    manager_name,
                )
                try:
                    manager.get_apk()
                    db_json[app_name]['version'] = remote_version
                    db_json[app_name]['source'] = manager_name
                    db_json[app_name]['file'] = manager.apk_path
                    break  # update successful
                except Exception as exc:  # NOQA
                    logging.warning('%r: %r', exc.__class__.__name__, str(exc))
                    continue  # try next manager

        # remove apps that are not in config any more
        for app_name in tuple(db_json.keys()):
            if app_name not in self.sources:
                print('Removing unconfigured app', app_name)
                remove_file(db_json[app_name]['file'])
                del db_json[app_name]

        self._write_db(db_json)

    def verify(self):
        """Verify all APKs with info from managers that provide the same version."""
        db_json = self._get_db()

        for app_name, app_managers in self.sources.items():
            print(' - Verifying app {}...'.format(app_name))
            try:
                for manager_name, manager in app_managers.items():
                    if manager.version == db_json[app_name]['version']:
                        manager.verify()
            except Exception as exc:  # NOQA
                logging.error(
                    'Integrity of app %r using manager %r could not be verified. Removing app.',
                    app_name, manager_name
                )
                logging.error('%r: %r', exc.__class__.__name__, str(exc))
                remove_file(db_json[app_name]['file'])

    def get_status(self):
        """Return the version, file and source of all APKs."""
        return self._get_db()
