# -*- coding: utf-8 -*-
"""Config sources."""

import os
import re
import tempfile

import requests

from .utils import get_apk_href, get_single_result


def get_wire_version(soup):
    """Return the version string found in HTML BeautifulSoup soup."""
    info = get_single_result(soup.select('a[href$=.apk]')).findNext('span')
    text = info.attrs['title'].strip().lower()
    return re.search(
        r'^version: (?P<version>(\d+\.)+\d+) ', text
    ).group('version')


def get_wire_sha256sum(soup, **_):
    """Return the sha256sum specified on download homepage."""
    info = get_single_result(soup.select('a[href$=.apk]')).findNext('span')
    text = info.attrs['title']. \
        lower().replace(' ', '').replace('\n', '').replace('<br>', '')
    return re.search(
        r'.*filechecksum\(sha256\):(?P<checksum>[0-9a-f]{64}).*', text
    ).group('checksum')


def get_wire_signature_sha256(soup, **_):
    """Return the sha256 fpr of the APK signature given on the homepage."""
    info = get_single_result(soup.select('a[href$=.apk]')).findNext('span')
    text = info.attrs['title']. \
        lower().replace(' ', '').replace('\n', '').replace('<br>', '')
    return re.search(
        r'.*certificatefingerprint\(sha256\):(?P<checksum>[0-9a-f]{64}).*',
        text
    ).group('checksum')


def get_whatsapp_version(soup):
    """Return the version string found in HTML BeautifulSoup soup."""
    version = get_single_result(soup.select('.version'))
    return version.text.strip().lower().split(' ')[1]


def get_firefox_version(soup):
    """Return the version string found in HTML BeautifulSoup soup."""
    return soup.select('html')[0].attrs['data-latest-firefox'].strip().lower()


def get_vlc_version(soup):
    """Return the latest version for vlc."""
    return soup.select('a')[-1].text.strip('/')


def get_signal_version(**_):
    """Return the version of the latest release for signal."""
    resp = requests.get('https://updates.signal.org/android/latest.json')
    resp.raise_for_status()
    return resp.json()['versionName']


def get_signal_sha256sum(**_):
    """Return the sha256 sum of the APK file given on the homepage."""
    resp = requests.get('https://updates.signal.org/android/latest.json')
    resp.raise_for_status()
    return resp.json()['sha256sum']


def get_signal_signature_sha256(soup, **_):
    """Return the sha256 fpr of the APK signature given on the homepage."""
    return get_single_result(soup.select('.fingerprint')).text


SOURCES = {
    'wire': {
        'wire.com': {
            'type': 'web',
            'priority': 10,
            'url': 'https://wire.com/download/',
            'apk_url': get_apk_href,
            'apk_version': get_wire_version,
            'apk_checksums': [
                ('SHA256', get_wire_sha256sum),
            ],
            'apk_signature_fingerprints': [
                ('SHA256', get_wire_signature_sha256),
                ('SHA256',
'16:26:E3:F8:5D:FD:84:34:F7:86:66:44:48:61:F4:E5:C8:FB:37:7A:28:4C:1C:30:4C:B9:D5:85:28:8F:A3:52'),
                ('SHA1', '3B:35:68:C9:0D:C9:2F:F2:FB:79:ED:89:BC:9A:8D:E3:9D:42:9B:9A'),
                ('MD5', 'F5:20:FE:7D:5D:92:16:F2:BB:25:4E:AC:42:B1:46:7F'),
            ],
        },
        'apkdownloadmirror': {
            'type': 'apkdownloadmirror',
            'project': 'com.wire/wire',
            'apk_signature_fingerprints': [
                ('SHA256',
'16:26:E3:F8:5D:FD:84:34:F7:86:66:44:48:61:F4:E5:C8:FB:37:7A:28:4C:1C:30:4C:B9:D5:85:28:8F:A3:52'),
                ('SHA1', '3B:35:68:C9:0D:C9:2F:F2:FB:79:ED:89:BC:9A:8D:E3:9D:42:9B:9A'),
                ('MD5', 'F5:20:FE:7D:5D:92:16:F2:BB:25:4E:AC:42:B1:46:7F'),
            ],
        },
    },
    'whatsapp': {
        'whatsapp.com': {
            'type': 'web',
            'url': 'https://www.whatsapp.com/android/',
            'apk_url': get_apk_href,
            'apk_version': get_whatsapp_version,
            'apk_signature_fingerprints': [
                ('SHA256',
'39:87:D0:43:D1:0A:EF:AF:5A:87:10:B3:67:14:18:FE:57:E0:E1:9B:65:3C:9D:F8:25:58:FE:B5:FF:CE:5D:44'),
                ('SHA1', '38:A0:F7:D5:05:FE:18:FE:C6:4F:BF:34:3E:CA:AA:F3:10:DB:D7:99'),
                ('MD5', '55:6C:60:19:24:9B:BC:0C:AB:70:49:51:78:D3:A9:D1'),
            ],
        },
    },
    'firefox': {
        'mozilla.org': {
            'type': 'web',
            'url': 'https://www.mozilla.org/en-US/firefox/android/all/',
            'apk_url': 'https://download.mozilla.org/?product=fennec-latest&os=android&lang=en-US',
            'apk_version': get_firefox_version,
            'apk_signature_fingerprints': [
                ('SHA256',
'A7:8B:62:A5:16:5B:44:94:B2:FE:AD:9E:76:A2:80:D2:2D:93:7F:EE:62:51:AE:CE:59:94:46:B2:EA:31:9B:04'),
                ('SHA1', '92:0F:48:76:A6:A5:7B:4A:6A:2F:4C:CA:F6:5F:7D:29:CE:26:FF:2C'),
                ('MD5', 'B1:E1:BC:EE:27:33:02:5E:CE:94:56:E4:19:A8:14:A3'),
            ],
        },
    },
    'mattermost-mobile': {
        'github.com': {
            'type': 'github',
            'repo': 'mattermost/mattermost-mobile',
            'apk_signature_fingerprints': [
                ('SHA256',
'5C:A7:32:AB:1F:65:7D:D9:E4:BE:FF:08:40:A8:B9:D1:9C:59:C3:0D:E3:AD:CF:4B:E6:A2:92:72:26:C1:1F:4F'),
                ('SHA1', 'E3:FB:91:EC:B1:A9:C2:3A:CF:64:31:FB:AC:EB:15:AC:68:A2:18:31'),
                ('MD5', '56:DD:47:FC:85:16:3B:01:90:2A:89:BC:A7:2C:4D:95'),
            ],
        },
    },
    'signal': {
        'signal.org': {
            'type': 'web',
            'priority': 10,
            'url': 'https://signal.org/android/apk/',
            'apk_url': 'https://updates.signal.org/android/Signal-website-release-{version}.apk',
            'apk_version': get_signal_version,
            'apk_checksums': [
                ('SHA256', get_signal_sha256sum),
            ],
            'apk_signature_fingerprints': [
                ('SHA256',
'29:F3:4E:5F:27:F2:11:B4:24:BC:5B:F9:D6:71:62:C0:EA:FB:A2:DA:35:AF:35:C1:64:16:FC:44:62:76:BA:26'),
                ('SHA256', get_signal_signature_sha256),
                ('SHA1', '45:98:9D:C9:AD:87:28:C2:AA:9A:82:FA:55:50:3E:34:A8:87:93:74'),
                ('MD5', 'D9:0D:B3:64:E3:2F:A3:A7:BD:A4:C2:90:FB:65:E3:10'),
            ],
        },
        'apkdownloadmirror': {
            'type': 'apkdownloadmirror',
            'project': 'org.thoughtcrime.securesms/signal-private-messenger',
            'apk_signature_fingerprints': [
                ('SHA256',
'29:F3:4E:5F:27:F2:11:B4:24:BC:5B:F9:D6:71:62:C0:EA:FB:A2:DA:35:AF:35:C1:64:16:FC:44:62:76:BA:26'),
                ('SHA1', '45:98:9D:C9:AD:87:28:C2:AA:9A:82:FA:55:50:3E:34:A8:87:93:74'),
                ('MD5', 'D9:0D:B3:64:E3:2F:A3:A7:BD:A4:C2:90:FB:65:E3:10'),
            ],
        },
        'apkplz': {
            'type': 'apkplz',
            'project': 'signal-private-messenger',
            'apk_signature_fingerprints': [
                ('SHA256',
'29:F3:4E:5F:27:F2:11:B4:24:BC:5B:F9:D6:71:62:C0:EA:FB:A2:DA:35:AF:35:C1:64:16:FC:44:62:76:BA:26'),
                ('SHA1', '45:98:9D:C9:AD:87:28:C2:AA:9A:82:FA:55:50:3E:34:A8:87:93:74'),
                ('MD5', 'D9:0D:B3:64:E3:2F:A3:A7:BD:A4:C2:90:FB:65:E3:10'),
            ],
        },
    },
    'wpsoffice': {
        'apkdownloadmirror': {
            'type': 'apkdownloadmirror',
            'project': 'cn.wps.moffice_eng/wps-office-pdf',
            'apk_signature_fingerprints': [
                ('SHA256',
'64:39:90:87:8D:3C:A8:39:52:A5:BE:5F:3E:58:D9:F8:BB:6C:DC:57:BF:0F:22:87:00:21:20:71:C6:8D:B3:D7'),
                ('SHA1', '72:66:E5:A0:58:B0:8D:4C:67:21:4E:68:1A:46:3E:AB:E4:03:4A:32'),
                ('MD5', ' 55:2E:BA:E6:B4:7E:AC:E3:02:58:64:9A:DB:82:87:B6'),
            ],
        },
        'apkplz': {
            'type': 'apkplz',
            'project': 'wps-office-pdf',
            'apk_signature_fingerprints': [
                ('SHA256',
'64:39:90:87:8D:3C:A8:39:52:A5:BE:5F:3E:58:D9:F8:BB:6C:DC:57:BF:0F:22:87:00:21:20:71:C6:8D:B3:D7'),
                ('SHA1', '72:66:E5:A0:58:B0:8D:4C:67:21:4E:68:1A:46:3E:AB:E4:03:4A:32'),
                ('MD5', ' 55:2E:BA:E6:B4:7E:AC:E3:02:58:64:9A:DB:82:87:B6'),
            ],
        },
    },
    'soundcloud': {
        'apkdownloadmirror': {
            'type': 'apkdownloadmirror',
            'project': 'com.soundcloud.android/soundcloud-music-amp-audio',
            'apk_signature_fingerprints': [
                ('SHA256',
'AF:F9:30:D6:71:FA:0A:57:B8:C4:1D:16:78:CC:2A:8E:A7:17:07:5A:74:E3:46:94:2A:14:0A:FA:44:13:39:D2'),
                ('SHA1', '13:C9:E5:90:0D:43:70:89:B7:23:24:B0:26:0F:3B:5A:0B:4E:02:7B'),
                ('MD5', '9B:4C:70:12:B9:AD:F3:D9:A3:34:54:56:07:51:84:3A'),
            ],
        },
        'apkplz': {
            'type': 'apkplz',
            'project': 'soundcloud-music-amp-audio',
            'apk_signature_fingerprints': [
                ('SHA256',
'AF:F9:30:D6:71:FA:0A:57:B8:C4:1D:16:78:CC:2A:8E:A7:17:07:5A:74:E3:46:94:2A:14:0A:FA:44:13:39:D2'),
                ('SHA1', '13:C9:E5:90:0D:43:70:89:B7:23:24:B0:26:0F:3B:5A:0B:4E:02:7B'),
                ('MD5', '9B:4C:70:12:B9:AD:F3:D9:A3:34:54:56:07:51:84:3A'),
            ],
        },
    },
    'mixcloud': {
        'apkdownloadmirror': {
            'type': 'apkdownloadmirror',
            'project': 'com.mixcloud.player/mixcloud-radio-amp-dj-mixes',
            'apk_signature_fingerprints': [
                ('SHA256',
'7B:8C:56:B9:6F:DB:AB:10:A7:D8:C7:2A:35:0F:54:3D:D1:2F:31:2D:E4:01:95:F8:B4:7E:79:29:8E:23:62:D2'),
                ('SHA1', '21:A2:EA:80:FF:C2:C6:EE:50:6A:3E:04:E6:3D:FD:94:6E:CB:AC:5E'),
                ('MD5', 'CE:0C:6B:73:4F:FB:D7:18:B2:6B:4A:B2:8A:7B:E1:1B'),
            ],
        },
        'apkplz': {
            'type': 'apkplz',
            'project': 'mixcloud-radio-amp-dj-mixes',
            'apk_signature_fingerprints': [
                ('SHA256',
'7B:8C:56:B9:6F:DB:AB:10:A7:D8:C7:2A:35:0F:54:3D:D1:2F:31:2D:E4:01:95:F8:B4:7E:79:29:8E:23:62:D2'),
                ('SHA1', '21:A2:EA:80:FF:C2:C6:EE:50:6A:3E:04:E6:3D:FD:94:6E:CB:AC:5E'),
                ('MD5', 'CE:0C:6B:73:4F:FB:D7:18:B2:6B:4A:B2:8A:7B:E1:1B'),
            ],
        },
    },
    'trello': {
        'apkdownloadmirror': {
            'type': 'apkdownloadmirror',
            'project': 'com.trello/trello',
            'apk_signature_fingerprints': [
                ('SHA256',
'5B:77:11:55:16:5A:20:F5:61:92:F0:A4:57:36:4F:18:A9:ED:F9:AC:55:30:DA:A3:3A:0B:C3:7F:63:0E:82:39'),
                ('SHA1', 'B2:F6:D2:21:9C:12:EF:B0:1B:76:E8:7F:87:A9:B9:42:86:BA:2C:C9'),
                ('MD5', '19:13:11:71:69:43:D0:3F:A3:85:57:B0:B9:1F:73:EC'),
            ],
        },
        'apkplz': {
            'type': 'apkplz',
            'project': 'trello',
            'apk_signature_fingerprints': [
                ('SHA256',
'5B:77:11:55:16:5A:20:F5:61:92:F0:A4:57:36:4F:18:A9:ED:F9:AC:55:30:DA:A3:3A:0B:C3:7F:63:0E:82:39'),
                ('SHA1', 'B2:F6:D2:21:9C:12:EF:B0:1B:76:E8:7F:87:A9:B9:42:86:BA:2C:C9'),
                ('MD5', '19:13:11:71:69:43:D0:3F:A3:85:57:B0:B9:1F:73:EC'),
            ],
        },
    },
    'vlc': {
        'get.videolan.org': {
            'type': 'web',
            'url': 'https://get.videolan.org/vlc-android/',
            'apk_url': 'https://get.videolan.org/vlc-android/{version}/VLC-Android-{version}-ARMv7.apk',
            'apk_version': get_vlc_version,
            'apk_signature_fingerprints': [
                ('SHA256',
'C8:76:8D:2C:EA:0C:4B:62:2E:41:9B:4B:47:15:98:19:46:82:1E:4E:BC:03:5F:B4:17:76:CA:D3:95:A7:F6:8E'),
                ('SHA1', 'EE:FB:C9:81:42:83:43:BB:DD:FF:F6:B2:3B:6B:D8:71:73:51:41:0C'),
                ('MD5', '51:1F:EA:1A:22:A7:B6:2E:BC:01:95:0C:16:7C:04:06'),
            ],
        },
    },
}

SETTINGS = {
    'repo_dir': os.path.join(
        os.path.dirname(os.path.dirname(__file__)), 'fdroid/repo/'
    ),
    'temp_dir': os.path.join(tempfile.gettempdir(), 'apk_schleuder/'),
    'keytool': 'keytool',
    'apksigner': '/opt/android_sdk/build-tools/25.0.1/apksigner',
}
SETTINGS['db_file'] = os.path.join(SETTINGS['repo_dir'], 'db.json')
