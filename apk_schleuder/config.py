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


def get_firefox_apk_url(_):
    """Return the static download url to firefox APK."""
    return 'https://download.mozilla.org/?product=fennec-latest&os=android&lang=en-US'


def get_firefox_version(soup):
    """Return the version string found in HTML BeautifulSoup soup."""
    return soup.select('html')[0].attrs['data-latest-firefox'].strip().lower()



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
                    'SHA256': \
'39:87:D0:43:D1:0A:EF:AF:5A:87:10:B3:67:14:18:FE:57:E0:E1:9B:65:3C:9D:F8:25:58:FE:B5:FF:CE:5D:44',
                    'SHA1': '38:A0:F7:D5:05:FE:18:FE:C6:4F:BF:34:3E:CA:AA:F3:10:DB:D7:99',
                    'MD5': '55:6C:60:19:24:9B:BC:0C:AB:70:49:51:78:D3:A9:D1',
                },
            },
        },
    },
    'firefox': {
        'mozilla.org': {
            'type': 'web',
            'config': {
                'url': 'https://www.mozilla.org/en-US/firefox/android/all/',
                'get_apk_url': get_firefox_apk_url,
                'get_apk_version': get_firefox_version,
                'apk_signature_fingerprints': {
                    'SHA256': \
'A7:8B:62:A5:16:5B:44:94:B2:FE:AD:9E:76:A2:80:D2:2D:93:7F:EE:62:51:AE:CE:59:94:46:B2:EA:31:9B:04',
                    'SHA1': '92:0F:48:76:A6:A5:7B:4A:6A:2F:4C:CA:F6:5F:7D:29:CE:26:FF:2C',
                    'MD5': 'B1:E1:BC:EE:27:33:02:5E:CE:94:56:E4:19:A8:14:A3',
                },
            },
        },
    },
    'faufablab': {
        'github.com': {
            'type': 'github',
            'config': {
                'repo': 'FAU-Inf2/fablab-android',
                'apk_signature_fingerprints': {
                    'SHA256': \
'9E:E0:7F:90:F6:E3:BE:97:CD:AC:E8:5D:00:AE:8C:84:13:99:25:FB:A5:7C:0B:D2:8A:90:54:F8:37:10:E9:62',
                    'SHA1': '70:FB:ED:80:C4:6C:B1:32:00:C7:30:81:27:69:5D:8D:AB:1C:69:8B',
                    'MD5': 'CC:54:03:C3:4A:0D:05:02:0E:A0:49:1A:BD:AC:81:34',
                },
            },
        },
    },
    'mattermost': {
        'github.com': {
            'type': 'github',
            'config': {
                'repo': 'mattermost/android',
                'apk_signature_fingerprints': {
                    'SHA256': \
'B1:36:5A:3D:8E:ED:77:EC:1E:D8:43:F8:36:D1:20:46:9A:4F:01:45:96:39:4C:FC:CD:20:79:57:1F:AA:E5:8C',
                    'SHA1': 'E0:98:D2:8D:54:DB:C2:27:EA:50:BD:B4:A2:97:53:70:AB:A3:12:A8',
                    'MD5':  'A4:0C:4A:E4:DE:01:5B:A5:E7:31:12:B4:14:76:F6:ED',
                },
            },
        },
    },
}

SETTINGS = {
    'repo_dir': os.path.join(
        os.path.dirname(os.path.dirname(__file__)), 'fdroid_repo/'
    ),
    'temp_dir': os.path.join(tempfile.gettempdir(), 'apk_schleuder/'),
    'keytool': 'keytool',
    'jarsigner': 'jarsigner',
}
