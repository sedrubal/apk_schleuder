# -*- coding: utf-8 -*-

"""Sources manager. Get meta information and APKs."""

import abc
from types import FunctionType
import os
from warnings import warn
import hashlib
import requests
from bs4 import BeautifulSoup
from . import utils
from . import verify

def manager_factory(manager_type):
    """Return the manager class for manager_type."""
    if manager_type == 'web':
        return WebManager
    else:
        raise ValueError('Manager type %s not found' % manager_type)


class BaseManager(object):
    """Abstract source manager."""

    __metaclass__ = abc.ABCMeta

    def __init__(self, name, repo_dir):
        self.name = name
        self.repo_dir = repo_dir

    @property
    def apk_path(self):
        """Return the destination path to APK file."""
        return os.path.join(self.repo_dir, '%s.apk' % self.name)

    @abc.abstractmethod
    def get_version(self):
        """Return a version string of the latest APK version."""
        pass

    @abc.abstractmethod
    def get_apk(self):
        """Generate the APK, verify it and return the path to APK file."""
        pass

    @abc.abstractmethod
    def clean(self):
        """Cleanup. Delete APK file (and other files)."""
        pass


class WebManager(BaseManager):
    """docstring for WebManager"""
    def __init__(self, name, repo_dir,
                 url, get_apk_url, get_apk_version, **kwargs):
        """
        name: The name of the app to manage
        url: The URL of the HTML download page
        get_apk_url: A function to parse the APK download URL from dl page
        get_apk_version: A function to parse the APK Version from dl page
        """
        super(WebManager, self).__init__(name, repo_dir)
        self.url = url
        self.get_apk_url = get_apk_url
        self.get_apk_version = get_apk_version
        self._soup = None
        self.get_apk_checksums = {}
        for key, value in kwargs.items():
            if key == 'get_apk_checksums':
                if all((x in hashlib.algorithms_available for x in value)):
                    self.get_apk_checksums = value
                else:
                    warn(
                        'Unrecognized hashing algorithm in %s.' %
                        ', '.join(value.keys())
                    )
                    warn(
                        'Recognized hashing algorithms are %s.' %
                        ', '.join(hashlib.algorithms_available)
                    )

            elif key == 'apk_signature_fingerprints':
                if all((x in ['SHA256', 'SHA1', 'MD5'] for x in value)):
                    self.apk_signature_fingerprints = value
                else:
                    warn(
                        'Unrecognized signature fingerprint type in %s.' %
                        ', '.join(value.keys())
                    )
                    warn(
                        'Recognized signature fingerprint types are %s' %
                        ', '.join(hashlib.algorithms_available)
                    )

    @property
    def soup(self):
        """Return the BeautifulSoup of the download webpage."""
        if not self._soup:
            resp = requests.get(self.url)
            if not resp.ok:
                warn('Status of request is not ok.')
            self._soup = BeautifulSoup(resp.content, 'html.parser')

        return self._soup

    def verify_apk_file(self):
        """Verify the downloaded APK file if checksums or fprs configured."""
        # Verify checksum
        for method, get_checksum in self.get_apk_checksums.items():
            try:
                verify.verify_checksum(
                    file_name=self.apk_path,
                    chksum=get_checksum(self.soup),
                    method=method,
                )
            except verify.ChecksumMissmatch as err:
                warn(str(err))
            else:
                print('  - %s checksum matches' % method)

        # Verify APK signature
        try:
            verify.verify_apk_sig(self.apk_path)
        except verify.CryptoVerificationError as err:
            warn(str(err))
        else:
            print('  - APK signature is valid')

        # Verify APK signature fingerprint
        def _get_fpr(arg):
            """Run arg if it's a function and return the ret val, else arg."""
            if isinstance(arg, FunctionType):
                return arg(self.soup)
            else:
                return arg

        fpr_sha256 = _get_fpr(self.apk_signature_fingerprints['SHA256'])
        fpr_sha1 = _get_fpr(self.apk_signature_fingerprints['SHA1'])
        fpr_md5 = _get_fpr(self.apk_signature_fingerprints['MD5'])

        if fpr_sha256 or fpr_sha1 or fpr_md5:
            try:
                verify.verify_apk_sig_fpr(
                    self.apk_path, fpr_sha256, fpr_sha1, fpr_md5
                )
            except verify.CryptoVerificationError as err:
                warn(str(err))
            else:
                print('  - signature fingerprint(s) matches')
        else:
            print('  - No signature fingerprint was given')

    def get_version(self):
        return self.get_apk_version(self.soup)

    def get_apk(self):
        apk_url = self.get_apk_url(self.soup)
        utils.download(self.apk_path, apk_url)
        self.verify_apk_file()
        return self.apk_path

    def clean(self):
        os.remove(self.apk_path)
