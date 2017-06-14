# -*- coding: utf-8 -*-
"""Sources manager. Get meta information and APKs."""

import abc
import hashlib
import logging
import os
import random
import re
import string

import requests
from bs4 import BeautifulSoup
from dateutil.parser import parse as parse_date

from . import utils, verify
from .config import SETTINGS


def manager_factory(manager_type):
    """Return the manager class for manager_type."""
    return {
        'web': WebManager,
        'github': GitHubManager,
        'apkdownloadmirror': ApkDownloadMirrorManager,
        'apkplz': ApkPlzManager,
    }[manager_type]


class BaseManager(object):
    """Abstract source manager."""

    __metaclass__ = abc.ABCMeta

    def __init__(self, name, priority=0):
        self.name = name
        self._version = None
        self.priority = priority

    @property
    def apk_path(self):
        """Return the destination path to APK file."""
        return os.path.join(SETTINGS['repo_dir'], '%s.apk' % self.name)

    @abc.abstractmethod
    def _get_version(self):
        """
        Return a version string of the latest APK version.

        Will be called by self._version property.
        """

    @property
    def version(self):
        """Return a version string of the latest APK version."""
        if not self._version:
            self._version = self._get_version()

        return self._version

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

    def __init__(self, name, priority=0, **kwargs):
        super(DownloadBasedManager, self).__init__(name, priority)
        self._apk_url = None
        self.get_apk_checksums = []
        self.apk_signature_fingerprints = []
        for key, value in kwargs.items():
            if key == 'get_apk_checksums':
                if all((x[0] in hashlib.algorithms_available for x in value)):
                    self.get_apk_checksums = value
                else:
                    logging.error(
                        'Unrecognized hashing algorithm in %s.',
                        ', '.join((x[0] for x in value))
                    )
                    logging.error(
                        'Recognized hashing algorithms are %s.',
                        ', '.join(hashlib.algorithms_available)
                    )

            elif key == 'apk_signature_fingerprints':
                if all((x[0] in ['SHA256', 'SHA1', 'MD5'] for x in value)):
                    self.apk_signature_fingerprints = value
                else:
                    logging.error(
                        'Unrecognized signature fingerprint type in %s.',
                        ', '.join((x[0] for x in value))
                    )
                    logging.error(
                        'Recognized signature fingerprint types are %s',
                        ', '.join(hashlib.algorithms_available)
                    )

    @property
    @abc.abstractproperty
    def apk_url(self):
        """Return the URL to download the desired APK file."""

    def get_apk(self):
        """Download and verify the APK. Return local file path."""
        if not self.apk_url:
            raise ValueError('APK download URL not found.')

        utils.download(url=self.apk_url, local_filename=self.apk_path)
        self.verify()
        return self.apk_path

    @abc.abstractmethod
    def _get_checksum(self, arg):
        """
        Evaluate the selfget_apk_checksums configs.

        arg is a given config from config.SOURCES
        Example call:
        >>> _get_checksum(self.get_apk_checksums['SHA256'])
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
        file_checksums = {}
        for method, get_checksum in self.get_apk_checksums:
            checksum = utils.clean_hexdigitstr(
                self._get_checksum(get_checksum)
            )
            if method not in file_checksums.keys():
                file_checksums[method] = verify.get_file_checksum(
                    file_name=self.apk_path,
                    method=method,
                )

            if checksum != file_checksums[method]:
                raise verify.ChecksumMissmatch(
                    file_name=self.apk_path,
                    method=method,
                    checksum_expected=file_checksums[method],
                    checksum_was=checksum,
                )

            print('  - %s checksum matches' % method)

    def verify_apk_signature(self):
        """Verify the APK vs. it's signature."""
        verify.verify_apk_sig(self.apk_path)  # raises CryptoVerificationError
        print('  - APK signature is valid')

    def verify_apk_signature_fprs(self):
        """Verify the APK signature fprs vs. all available fprs."""
        if not self.apk_signature_fingerprints:
            print('  - No signature fingerprint was given')
            return

        real_fprs = verify.get_apk_sig_fpr(self.apk_path)
        for method, get_fpr in self.apk_signature_fingerprints:
            fpr = utils.clean_hexdigitstr(self._get_fpr(get_fpr))
            if real_fprs[method]:
                if fpr != real_fprs[method]:
                    raise verify.CryptoVerificationError(
                        file_name=self.apk_path,
                        message='{0} fingerprint did not match. '
                        'Expected {1} but was {2}'.format(
                            method, fpr, real_fprs[method]
                        )
                    )
                else:
                    print('  - %s signature fingerprint matches' % method)

    def verify(self):
        """Verify the downloaded APK file if checksums or fprs configured."""
        self.verify_checksums()
        self.verify_apk_signature()
        self.verify_apk_signature_fprs()


class WebManager(DownloadBasedManager):
    """Download APKs from project homepages."""

    def __init__(self, name, url, apk_url, apk_version, priority=2, **kwargs):
        """
        name: The name of the app to manage
        url: The URL of the HTML download page
        get_apk_url: A function to parse the APK download URL from dl page
        get_apk_version: A function to parse the APK Version from dl page
        """
        super(WebManager, self).__init__(name, priority=priority, **kwargs)
        self.url = url
        self.get_apk_url = apk_url
        self.get_apk_version = apk_version
        self._soup = None

    @property
    def soup(self):
        """Return the BeautifulSoup of the download webpage."""
        if not self._soup:
            resp = requests.get(self.url)
            if not resp.ok:
                logging.warning('Status of request is not ok.')
            self._soup = BeautifulSoup(resp.content, 'html.parser')

        return self._soup

    def _get_version(self):
        return utils.clean_version_string(
            self.get_apk_version(soup=self.soup)
        )

    @property
    def apk_url(self):
        """Return the URL to download the APK file."""
        if not self._apk_url:
            self._apk_url = utils.get_str_or_return_val(
                self.get_apk_url,
                version=self.version,
                soup=self.soup,
            )

        return self._apk_url

    def _get_fpr(self, arg):
        return utils.get_str_or_return_val(
            arg,
            version=self.version,
            soup=self.soup,
        )

    _get_checksum = _get_fpr


class GitHubManager(DownloadBasedManager):
    """Download APKs from GitHub Release page."""

    RELEASE_API = 'https://api.github.com/repos/{repo}/releases/latest'

    def __init__(self, name, repo, priority=1, **kwargs):
        super(GitHubManager, self).__init__(name, priority=priority, **kwargs)
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

    def _get_version(self):
        return utils.clean_version_string(self.api_json['tag_name'])

    def verify(self):
        super(GitHubManager, self).verify()
        if self._latest_apk_asset()['size'] == os.path.getsize(self.apk_path):
            print('  - File size matches GitHub API')
        else:
            logging.error('  - File size differs from value in GitHub API.')

    def _latest_apk_asset(self):
        """Return the asset from api_json that seems to be the desired apk."""

        def _check_asset_apk(asset):
            """Check if an asset is a valid APK. Return True if it is."""
            return all(
                {
                    asset['name'].endswith('.apk'),
                    asset['content_type'] == 'application/vnd.android.package-archive',
                    asset['state'] == 'uploaded',
                }
            )

        for asset in self.api_json['assets']:
            if _check_asset_apk(asset):
                return asset

    @property
    def apk_url(self):
        if not self._apk_url:
            self._apk_url = self._latest_apk_asset()['browser_download_url']

        return self._apk_url

    def _get_fpr(self, arg):
        return utils.get_str_or_return_val(
            arg,
            api_json=self.api_json,
        )

    _get_checksum = _get_fpr


class ApkDownloadMirrorManager(WebManager):
    """Download APKs from apkdownloadmirror.com."""

    URL = 'https://apkdownloadmirror.com/apk/{project}'
    APK_DOWNLOAD_URL = 'http://file2.apkupdate.com/dl/' + \
        '{rnd}/download/{year}/{month:02}/{apk_id}-{build_id}.apk'

    def __init__(self, name, project, **kwargs):
        super(ApkDownloadMirrorManager, self).__init__(
            name=name,
            url=ApkDownloadMirrorManager.URL.format(project=project),
            apk_url=ApkDownloadMirrorManager.apkdownloadmirror_get_apk_url,
            apk_version=ApkDownloadMirrorManager.apkdownloadmirror_get_apk_version,
            **kwargs
        )
        self.get_apk_checksums += [
            ('SHA1', ApkDownloadMirrorManager.apkdownloadmirror_get_sha1_sum),
            ('MD5', ApkDownloadMirrorManager.apkdownloadmirror_get_md5_sum),
        ]
        self.apk_signature_fingerprints.append(
            ('SHA1', ApkDownloadMirrorManager.apkdownloadmirror_get_apk_sig_fpr),
        )

    @staticmethod
    def apkdownloadmirror_get_md5_sum(soup, **_):
        """Return the MD5 sum from apkdownloadmirror.com site."""
        return soup.find(text=re.compile(r'File APK Md5:')).next.text.strip()

    @staticmethod
    def apkdownloadmirror_get_sha1_sum(soup, **_):
        """Return the SHA1 sum from apkdownloadmirror.com site."""
        return soup.find(text=re.compile(r'File APK Sha1:')).next.text.strip()

    @staticmethod
    def apkdownloadmirror_get_apk_sig_fpr(soup, **_):
        """Return the fpr of the apk sign. from apkdownloadmirror.com site."""
        return soup.find(text=re.compile(r'Signature:')).next.text.strip()

    @staticmethod
    def apkdownloadmirror_get_apk_url(soup, **_):
        """Return the download url for the APK on apkdownloadmirror.com site."""
        build_id = list(
            soup.select('.apks .title span')[0].children
        )[1].strip().split(' ')[1].strip('()')
        date = parse_date(soup.find(text=re.compile(r'\s*Date:\s*')).next)
        apk_id = soup.select('a[data-tag]')[0].\
            attrs['data-tag'][len('apkupdate-'):]
        rnd = ''.join(
            (
                random.choice(string.ascii_letters + string.digits)
                for _ in range(62)
            )
        )
        return ApkDownloadMirrorManager.APK_DOWNLOAD_URL.format(
            rnd=rnd,
            year=date.year,
            month=date.month,
            apk_id=apk_id,
            build_id=build_id
        )

    @staticmethod
    def apkdownloadmirror_get_apk_version(soup):
        """Return the latest version of the APK on apkdownloadmirror.com site."""
        return list(
            soup.select('.apks .title span')[0].children
        )[1].strip().split(' ')[0]


class ApkPlzManager(WebManager):
    """Download APKs from apkplz.com."""

    URL = 'https://apkplz.com/android-apps/{project}-apk-download'
    APK_DOWNLOAD_URL = 'https://download.apkplz.com/apk/{domain}/{apk_name}-apkplz.com.apk'

    def __init__(self, name, project, **kwargs):
        """project=name of app in apkplz url (without -apk-download)."""
        super(ApkPlzManager, self).__init__(
            name=name,
            url=ApkPlzManager.URL.format(project=project),
            apk_url=self.apkplz_get_apk_url,
            apk_version=ApkPlzManager.apkplz_get_apk_version,
            **kwargs
        )
        self.project = project

    def apkplz_get_apk_url(self, soup, **_):
        """Return the download url for the APK on apkplz.com."""
        apk_name = soup.select('#download_form')[0]. \
            attrs['action'].split('/')[-1]
        domain = re.match(
            r'^.*\((?P<domain>[\w\.]+)\).*$',
            soup.select('title')[0].text,
        ).group('domain')
        return ApkPlzManager.APK_DOWNLOAD_URL.format(
            domain=domain.replace('.', '/'),
            apk_name=apk_name,
        )

    @staticmethod
    def apkplz_get_apk_version(soup):
        """Return the version of the latest APK on apkplz.com."""
        return soup.select('span[itemprop=softwareVersion]')[0].text
