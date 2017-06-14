# APK Schleuder

Download APKs from shady sources and put them into a f-droid repo.

[![Code Health](https://landscape.io/github/sedrubal/apk_schleuder/master/landscape.svg?style=flat)](https://landscape.io/github/sedrubal/apk_schleuder/master)

## Installation

- (Create a virtualenv: `python3 -m virtualenv -p python3 --system-site-packages .venv && . ./.venv/bin/activate`)
- Install apk_schleuder: `pip install git+https://github.com/sedrubal/apk_schleuder.git` or clone the repo and run `./setup.py install`
- Install (java) keytool and jarsigner

## Config

Create a config under `config.py`. You can also create a symlink to `config_example.py`.

## Usage

`python3 -m apk_schleuder`

## Add new APKs

- find a source to download the APK (e.g. apkdownloadmirror.com, apkplz.com, github.com, a website, ...)
- create a new entry in `config.py`:

```py
'app_name': {
    'source_1': {
        'type': 'source_type',
        ...,  # source type specific config
        'apk_signature_fingerprints': [
            ('SHA256', \
'5B:77:11:55:16:5A:20:F5:61:92:F0:A4:57:36:4F:18:A9:ED:F9:AC:55:30:DA:A3:3A:0B:C3:7F:63:0E:82:39'),
            ('SHA1', 'B2:F6:D2:21:9C:12:EF:B0:1B:76:E8:7F:87:A9:B9:42:86:BA:2C:C9'),
            ('MD5', '19:13:11:71:69:43:D0:3F:A3:85:57:B0:B9:1F:73:EC'),
        ],
    },
    ...,  # other sources...
},
```

### Get the fingerprints

- Get an APK from a trustworthy source
- unzip it
- search for the signing certificate in folder `META-INF` (e.g. `CERT.RSA`)
- run `keytool -printcert -file $certfile` and put the fingerprints into `config.py`

## License

(c) 2017 sedrubal - [MIT](https://opensource.org/licenses/MIT)
