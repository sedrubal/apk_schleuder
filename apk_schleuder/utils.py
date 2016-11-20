# -*- coding: utf-8 -*-

"""Some utils."""

from warnings import warn
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


def check_single_result(results):
    """Check if the length of results is 1. Otherwise print a warning."""
    if len(results) > 1:
        warn('Expected to find only one result for selector, but found more.')
    elif len(results) < 1:
        warn('Expected to find one result for selector, but found none.')


def get_apk_href(soup):
    """Return the href value of the first .apk href link in soup."""
    urls = soup.select('a[href$=.apk]')
    check_single_result(urls)

    return urls[0].attrs['href']


def clean_version_string(version_str):
    """Return a cleaned version string."""
    return version_str.lower().lstrip('v').replace('-release', '')
