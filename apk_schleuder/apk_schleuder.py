# -*- coding: utf-8 -*-

"""Main module"""

import os
import json
from warnings import warn
from distutils.version import StrictVersion

from .config import SETTINGS
from .sources_manager import manager_factory


class APKSchleuder(object):
    """Core of APK Schleuder"""

    def __init__(self, config_sources):
        """Read config and create sources."""
        self.sources = {}
        for app_name, app_managers in config_sources.items():
            self.sources[app_name] = {}
            for manager_name, manager_config in app_managers.items():
                manager = manager_factory(manager_config['type'])(
                    name=app_name, **manager_config['config']
                )
                self.sources[app_name][manager_name] = manager

    def get_latest_versions(self):
        """
        Return a dict containing the latest versions of apps like this:

        >>> get_latest_version()
        {
            'appname1': {'version': '0.1.2', 'manager_name': 'manager1_name'},
            'appname2': {'version': '1.33.7', 'manager_name': 'manager2_name'},
        }
        """
        results = {}
        for app_name, app_managers in self.sources.items():
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
                warn('{0}: {1}'.format(err.__class__.__name__, str(err)))

        return results

    def _get_db(self):
        """Open, read and update the db json."""
        try:
            with open(SETTINGS['db_file'], 'r') as db_file:
                db_json = json.load(db_file)

        except (FileNotFoundError, json.decoder.JSONDecodeError):
            db_json = {}

        def _validate_version(cfg_app):
            try:
                return StrictVersion(cfg_app.get('version', '0.0.0'))
            except ValueError:
                return StrictVersion('0.0.0')

        def _validate_file(cfg_app):
            if not os.path.isfile(cfg_app.get('file', '')):
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

        latest_versions = self.get_latest_versions()

        for app_name in self.sources:
            local_version = db_json[app_name]['version']
            remote_version = latest_versions[app_name]['version']
            if remote_version > local_version:
                manager_name = latest_versions[app_name]['manager_name']
                manager = self.sources[app_name][manager_name]
                print(
                    'Updating', app_name,
                    'from', local_version,
                    'to', remote_version,
                    'using', manager_name,
                )
                try:
                    manager.get_apk()
                    db_json[app_name]['version'] = remote_version
                    db_json[app_name]['source'] = manager_name
                    db_json[app_name]['file'] = manager.apk_path
                except Exception as err:
                    warn('{0}: {1}'.format(err.__class__.__name__, str(err)))

        self._write_db(db_json)


    def get_status(self):
        """Return the version, file and source of all APKs."""
        return self._get_db()
