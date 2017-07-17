# -*- coding: utf-8 -*-
"""Some utils."""

import logging
import os
import string

import requests


def download(url, local_filename):
    """Download a file from url to local_filename."""
    resp = requests.get(url, stream=True)
    if not resp.ok:
        resp.raise_for_status()

    with open(local_filename, 'w+b') as local_file:
        for chunk in resp.iter_content(chunk_size=1024):
            if chunk:
                local_file.write(chunk)


def get_single_result(results):
    """Return first element of a list. Print a warning if len(result) > 1."""
    if len(results) > 1:
        logging.warning(
            'Expected to find only one result for selector, but found more.'
        )
    elif len(results) < 1:
        raise IndexError('There is no result.')

    return results[0]


def get_apk_href(soup, **_):
    """Return the href value of the first .apk href link in soup."""
    urls = soup.select('a[href$=.apk]')
    return get_single_result(urls).attrs['href']


def clean_version_string(version_str):
    """Return a cleaned version string."""
    return version_str.lower().lstrip('v').replace('-release', '')


def clean_hexdigitstr(fingerprint):
    """Return a cleaned fingerprint or checksum string."""
    return ''.join((c.lower() for c in fingerprint if c in string.hexdigits))


def get_str_or_return_val(arg, **kwargs):
    """Return arg(**kwargs) if arg is a function, else arg."""
    return arg(**kwargs) if callable(arg) else arg.format(**kwargs)

def remove_file(file_name):
    """Remove file file_name and report errors."""
    try:
        os.remove(file_name)
    except Exception as exc:  # NOQA
        logging.error(
            'Could not remove file %r.', file_name
        )
        logging.error('%r: %r', exc.__class__.__name__, str(exc))
