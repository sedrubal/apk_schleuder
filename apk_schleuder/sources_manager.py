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

from .config import SETTINGS

def manager_factory(manager_type):
    """Return the manager class for manager_type."""
    if manager_type == 'web':
        return WebManager
    elif manager_type == 'github':
        return GitHubManager
    else:
        raise ValueError('Manager type %s not found' % manager_type)


class BaseManager(object):
    """Abstract source manager."""

    __metaclass__ = abc.ABCMeta

    def __init__(self, name):
        self.name = name

    @property
    def apk_path(self):
        """Return the destination path to APK file."""
        return os.path.join(SETTINGS['repo_dir'], '%s.apk' % self.name)

    @abc.abstractmethod
    def get_version(self):
        """Return a version string of the latest APK version."""

    @abc.abstractmethod
    def get_apk(self):
        """Generate the APK, verify it and return the path to APK file."""

    @abc.abstractmethod
    def verify(self):
        """Verify the local APK file."""

    def clean(self):
        """Cleanup. Delete APK file (and other files - can be overwritten)."""
        os.remove(self.apk_path)


class DownloadBasedManager(BaseManager):
    """A parent class for download based managers."""

    __metaclass__ = abc.ABCMeta

    def __init__(self, name, **kwargs):
        super(DownloadBasedManager, self).__init__(name)
        self._apk_url = None
        self.get_apk_checksums = {}
        self.apk_signature_fingerprints = {}
        for key, value in kwargs.items():
            if key == 'get_apk_checksums':
                if all((x[0] in hashlib.algorithms_available for x in value)):
                    self.get_apk_checksums = value
                else:
                    warn(
                        'Unrecognized hashing algorithm in %s.' %
                        ', '.join((x[0] for x in value))
                    )
                    warn(
                        'Recognized hashing algorithms are %s.' %
                        ', '.join(hashlib.algorithms_available)
                    )

            elif key == 'apk_signature_fingerprints':
                if all((x[0] in ['SHA256', 'SHA1', 'MD5'] for x in value)):
                    self.apk_signature_fingerprints = value
                else:
                    warn(
                        'Unrecognized signature fingerprint type in %s.' %
                        ', '.join((x[0] for x in value))
                    )
                    warn(
                        'Recognized signature fingerprint types are %s' %
                        ', '.join(hashlib.algorithms_available)
                    )

    @property
    @abc.abstractproperty
    def apk_url(self):
        """Return the URL to download the desired APK file."""

    def get_apk(self):
        if not self.apk_url:
            raise ValueError('APK download URL not found.')

        utils.download(self.apk_path, self.apk_url)
        self.verify()
        return self.apk_path

    @abc.abstractmethod
    def _get_checksum(self, arg):
        """
        Evaluate the selfget_apk_checksums configs

        arg is a given config from config.SOURCES
        Example call:
        >>> _get_fpr(self.get_apk_checksums['SHA256'])
        """

    @abc.abstractmethod
    def _get_fpr(self, arg):
        """
        Evaluate the apk_signature_fingerprints configs.

        arg is a given config from config.SOURCES
        Example call:
        >>> _get_fpr(self.apk_signature_fingerprints['SHA256'])
        """

    def verify_checksums(self):
        """Verify all available checksums against downloaded file."""
        checked_checksums = {}
        for method, get_checksum in self.get_apk_checksums:
            try:
                checksum = self._get_checksum(get_checksum)
                if checked_checksums.get(method):
                    if checksum != checked_checksums[method]:
                        raise verify.ChecksumMissmatch(
                            file_name=self.apk_path,
                            method=method,
                            checksum_expected=checksum,
                            checksum_was=checked_checksums[method],
                        )
                    else:
                        continue  # same chksum was already checked
                else:
                    verify.verify_checksum(
                        file_name=self.apk_path,
                        chksum=checksum,
                        method=method,
                    )
                    checked_checksums[method] = checksum
            except verify.ChecksumMissmatch as err:
                warn(str(err))
            else:
                print('  - %s checksum matches' % method)

    def verify_apk_signature(self):
        """Verify the APK vs. it's signature."""
        try:
            verify.verify_apk_sig(self.apk_path)
        except verify.CryptoVerificationError as err:
            warn(str(err))
        else:
            print('  - APK signature is valid')

    def verify_apk_signature_fprs(self):
        """Verify the APK signature fprs vs. all available fprs."""

        if not self.apk_signature_fingerprints:
            print('  - No signature fingerprint was given')
            return

        real_fprs = verify.get_apk_sig_fpr(self.apk_path)
        for method, get_fpr in self.apk_signature_fingerprints:
            try:
                fpr = self._get_fpr(get_fpr).lower().replace(':', '')
                if real_fprs[method]:
                    if fpr != real_fprs[method]:
                        raise verify.CryptoVerificationError(
                            file_name=self.apk_path,
                            message='{0} fingerprint did not match. Expected {1} but was {2}'.
                            format(method, fpr, real_fprs[method])
                        )
                    else:
                        print('  - %s signature fingerprint matches' % method)
            except verify.ChecksumMissmatch as err:
                warn(str(err))

    def verify(self):
        """Verify the downloaded APK file if checksums or fprs configured."""
        self.verify_checksums()
        self.verify_apk_signature()
        self.verify_apk_signature_fprs()


class WebManager(DownloadBasedManager):
    """Download APKs from their project homepages."""
    def __init__(self, name, url, get_apk_url, get_apk_version, **kwargs):
        """
        name: The name of the app to manage
        url: The URL of the HTML download page
        get_apk_url: A function to parse the APK download URL from dl page
        get_apk_version: A function to parse the APK Version from dl page
        """
        super(WebManager, self).__init__(name, **kwargs)
        self.url = url
        self.get_apk_url = get_apk_url
        self.get_apk_version = get_apk_version
        self._soup = None

    @property
    def soup(self):
        """Return the BeautifulSoup of the download webpage."""
        if not self._soup:
            resp = requests.get(self.url)
            if not resp.ok:
                warn('Status of request is not ok.')
            self._soup = BeautifulSoup(resp.content, 'html.parser')

        return self._soup

    def get_version(self):
        return self.get_apk_version(self.soup)

    @property
    def apk_url(self):
        if not self._apk_url:
            self._apk_url = self.get_apk_url(self.soup)

        return self._apk_url

    def _get_fpr(self, arg):
        if isinstance(arg, FunctionType):
            return arg(self.soup)
        else:
            return arg

    _get_checksum = _get_fpr


class GitHubManager(DownloadBasedManager):
    """Download APKs from GitHub Release page."""
    RELEASE_API = 'https://api.github.com/repos/{repo}/releases/latest'

    def __init__(self, name, repo, **kwargs):
        super(GitHubManager, self).__init__(name, **kwargs)
        self.repo = repo
        self._api_json = None

    @property
    def api_json(self):
        """Return the JSON from API of the latest release end node."""
        if not self._api_json:
            resp = requests.get(
                GitHubManager.RELEASE_API.format(repo=self.repo)
            )
            if not resp.ok:
                resp.raise_for_status()

            self._api_json = resp.json()

        return self._api_json

    def get_version(self):
        return self.api_json['tag_name'].lower().lstrip('v')

    @property
    def apk_url(self):
        def _check_asset_apk(asset):
            """Checks if an asset is a valid APK. Return True if it is."""
            return all({
                asset['name'].endswith('.apk'),
                asset['content_type'] == 'application/vnd.android.package-archive',
                asset['state'] == 'uploaded',
            })

        if not self._apk_url:
            for asset in self.api_json['assets']:
                if _check_asset_apk(asset):
                    self._apk_url = asset['browser_download_url']

        return self._apk_url

    def _get_fpr(self, arg):
        if isinstance(arg, FunctionType):
            return arg(self.api_json)
        else:
            return arg

    _get_checksum = _get_fpr
