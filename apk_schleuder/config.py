# -*- coding: utf-8 -*-

"""Config sources."""

import re
import os
import tempfile

from .utils import check_single_result, get_apk_href

def get_wire_version(soup):
    """Return the version string found in HTML BeautifulSoup soup."""
    versions = soup.select('.info')
    check_single_result(versions)

    text = versions[0].attrs['title'].strip().lower()
    return re.search(
        r'^version: (?P<version>(\d+\.)+\d+) ', text
    ).group('version')


def get_wire_sha256sum(soup):
    """Return the sha256sum specified on download homepage."""
    versions = soup.select('.info')
    check_single_result(versions)

    text = versions[0].attrs['title']. \
        lower().replace(' ', '').replace('\n', '').replace('<br>', '')
    return re.search(
        r'.*filechecksum\(sha256\):(?P<checksum>[0-9a-f]{64}).*',
        text
    ).group('checksum')


def get_wire_signature_sha256(soup):
    """Return the sha256 fpr of the APK signature given on the homepage."""
    versions = soup.select('.info')
    check_single_result(versions)

    text = versions[0].attrs['title']. \
        lower().replace(' ', '').replace('\n', '').replace('<br>', '')
    return re.search(
        r'.*certificatefingerprint\(sha256\):(?P<checksum>[0-9a-f]{64}).*',
        text
    ).group('checksum')


def get_whatsapp_version(soup):
    """Return the version string found in HTML BeautifulSoup soup."""
    versions = soup.select('.version')
    check_single_result(versions)

    return versions[0].text.strip().lower().split(' ')[1]


SOURCES = {
    'wire': {
        'wire.com': {
            'type': 'web',
            'config': {
                'url': 'https://wire.com/download/',
                'get_apk_url': get_apk_href,
                'get_apk_version': get_wire_version,
                'get_apk_checksums': {
                    'SHA256': get_wire_sha256sum,
                },
                'apk_signature_fingerprints': {
                    'SHA256': get_wire_signature_sha256,
                    'SHA1': '3B:35:68:C9:0D:C9:2F:F2:FB:79:ED:89:BC:9A:8D:E3:9D:42:9B:9A',
                    'MD5': 'F5:20:FE:7D:5D:92:16:F2:BB:25:4E:AC:42:B1:46:7F',
                },
            },
        },
    },
    'whatsapp': {
        'whatsapp.com': {
            'type': 'web',
            'config': {
                'url': 'https://www.whatsapp.com/android/',
                'get_apk_url': get_apk_href,
                'get_apk_version': get_whatsapp_version,
                'apk_signature_fingerprints': {
                    'SHA256': '39:87:D0:43:D1:0A:EF:AF:5A:87:10:B3:67:14:18:FE:57:E0:E1:9B:65:3C:9D:F8:25:58:FE:B5:FF:CE:5D:44',
                    'SHA1': '38:A0:F7:D5:05:FE:18:FE:C6:4F:BF:34:3E:CA:AA:F3:10:DB:D7:99',
                    'MD5': '55:6C:60:19:24:9B:BC:0C:AB:70:49:51:78:D3:A9:D1',
                },
            },
        },
    },
    'faufablab': {
        'github.com': {
            'type': 'github',
            'config': {
                'repo': 'FAU-Inf2/fablab-android',
            }
        }
    }
}

SETTINGS = {
    'repo_dir': os.path.join(
        os.path.dirname(os.path.dirname(__file__)), 'fdroid_repo/'
    ),
    'temp_dir': os.path.join(tempfile.gettempdir(), 'apk_schleuder/'),
    'keytool': 'keytool',
    'jarsigner': 'jarsigner',
}
