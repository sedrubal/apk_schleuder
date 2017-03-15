"""Verification routines."""

import os
import re
import hashlib
from subprocess import call, run, DEVNULL, PIPE
from zipfile import ZipFile

from .config import SETTINGS


class CryptoVerificationError(ValueError):
    """Exception for failed verifications."""

    def __init__(self, file_name, message=''):
        msg = 'Verification for %s failed.' % file_name
        if message:
            msg += ' ' + message
        super(CryptoVerificationError, self).__init__(msg)
        self.file_name = file_name


class ChecksumMissmatch(CryptoVerificationError):
    """Exception on checksum missmatche."""

    def __init__(self, file_name, method, checksum_expected, checksum_was):
        super(ChecksumMissmatch, self).__init__(
            file_name=file_name,
            message='{0} checksum did not match. Expected {1} but was {2}'.
            format(
                method,
                checksum_expected,
                checksum_was,
            )
        )


def verify_checksum(file_name, chksum, method='SHA256'):
    """Verify the sha256sum of file_name. Raise an error if it missmatches."""
    hasher = hashlib.new(method)
    with open(file_name, "rb") as apk_file:
        for chunk in iter(lambda: apk_file.read(4096), b""):
            hasher.update(chunk)

    if hasher.hexdigest() != chksum:
        raise ChecksumMissmatch(file_name, method, chksum, hasher.hexdigest())


def _extract_certificate(file_name):
    """Extract the cert of an APK and return the extracted file name."""
    apk_zip = ZipFile(file_name)
    cert_file = None
    cert_file_name_regexp = re.compile(r'^META-INF\/.*\.[RD]SA$')
    for zipped_file in apk_zip.filelist:
        if cert_file_name_regexp.match(zipped_file.filename):
            cert_file = zipped_file
            break
    else:
        raise CryptoVerificationError(
            file_name, message='No certificate found in APK. Is it signed?'
        )

    apk_zip.extract(cert_file, SETTINGS['temp_dir'])
    return os.path.join(SETTINGS['temp_dir'], cert_file.filename)


def get_apk_sig_fpr(file_name):
    """Return the APK signature fingerprints."""
    cert_file_name = _extract_certificate(file_name)
    result = run(
        [SETTINGS['keytool'], '-printcert', '-file', cert_file_name],
        stdout=PIPE,
    )
    os.remove(cert_file_name)

    fpr_regexp = re.compile(
        r'.*certificatefingerprints:' +
        r'md5(?P<MD5>((:[0-9a-f]{2}){16}))' +
        r'sha1(?P<SHA1>((:[0-9a-f]{2}){20}))' +
        r'sha256(?P<SHA256>((:[0-9a-f]{2}){32}))' +
        r'.*'
    )
    stdout_text = result.stdout.decode('utf8').\
        replace(' ', '').replace('\t', '').replace('\n', '').lower()
    matches = fpr_regexp.search(stdout_text)

    return {
        m: matches.group(m).replace(':', '')
        for m in ['SHA256', 'SHA1', 'MD5']
    }


def verify_apk_sig(apk_file_name):
    """Verify the APK signature."""
    if call(
        [SETTINGS['jarsigner'], '-verify', apk_file_name], stdout=DEVNULL
    ) != 0:
        raise CryptoVerificationError(apk_file_name)
