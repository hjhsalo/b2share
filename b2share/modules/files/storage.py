# -*- coding: utf-8 -*-
#
# This file is part of EUDAT B2Share.
# Copyright (C) 2017 CERN.
#
# B2Share is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version.
#
# B2Share is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with B2Share; if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.
#
# In applying this license, CERN does not
# waive the privileges and immunities granted to it by virtue of its status
# as an Intergovernmental Organization or submit itself to any jurisdiction.

"""B2share Storage Class."""

from pathlib import PurePosixPath
from urllib.parse import urlparse, unquote

from flask import make_response, current_app, abort
from flask_login import current_user
from invenio_files_rest.storage.pyfs import PyFSFileStorage, \
    pyfs_storage_factory
from invenio_oauthclient.handlers import token_getter
import requests

from b2handle.handleclient import EUDATHandleClient

def _get_epic_pid_from_handle_url(handle_url):
    handle_url_p = urlparse(handle_url)

    # Drop the first '/' -character from 
    # urlparsed path to form an ePIC PID
    epic_pid = handle_url_p.path[1:]

    return epic_pid

def _resolve_redirect_url_of_epic_pid(epic_pid):
    eudat_handle_client = EUDATHandleClient()
    pid_info =  eudat_handle_client.\
            retrieve_handle_record(epic_pid)
    # Check that handle client returned something meaningful
    if not pid_info:
        return None
    return pid_info.get('URL', None)

def _is_http_uri(url):
    file_url_p = urlparse(url)

    if not file_url_p.scheme == 'https':
        if not file_url_p.scheme == 'http':
            return False

    return True

def _check_file_access(b2stage_url, epic_pid, b2access_token=None, email=None): 
    b2stage_jwt = None

    # import wdb
    # wdb.set_trace()

    # Fetch anonymous token if b2access_token and email are not provided
    if b2access_token and email:
        payload = { 'authscheme':'OpenID', 'username':email, 'token':b2access_token }
        b2stage_jwt = _get_jwt_token(b2stage_url, payload)
    else:
        b2stage_jwt = _get_jwt_token(b2stage_url)

    if b2stage_jwt is None:
        return None

    b2stage_pids_endpoint = '/api/pids'
    b2stage_registered_endpoint = '/api/registered'

    headers = {"Authorization": "Bearer " + b2stage_jwt, 'Connection':'close', 'Cache-Control': 'no-cache'}
    params = {}
    # Note>: adds '/' to ePIC PID
    url = b2stage_url + b2stage_pids_endpoint + '/' + epic_pid
    resp = requests.get(url, headers=headers, params=params)

    # TODO: Check for errors in 'errors'-key in JSON.
    if not resp.status_code == 200:
        return None
    
    file_url = resp.json().get('Response', None).get('data', None).get('URL', None)

    # Check file_url is at the defined B2STAGE instance
    if not b2stage_url in file_url:
        return None

    # Check that file_url points to api/registered -endpoint
    # that is used to download files.
    file_url_p = urlparse(file_url)

    # Check that the URL is HTTPS.
    # We only allow HTTPS, since request will contain JWT access token.
    if not file_url_p.scheme == 'https':
        return None

    # Check the url points to 'api/registered'
    # This check could be improved for corner cases:
    # e.g. 'api/incorrect/api/registered/file/path'
    # will be considered valid, which it is not.
    if not b2stage_registered_endpoint in file_url_p.path:
        return None

    if b2access_token and email:
        params = {'download': 'true'}
        resp = requests.head(url, headers=headers, params=params)
    else:
        resp = requests.get(file_url, headers=headers, params=params)
    # resp = requests.get(file_url, headers=headers, params=params)
    # We cannot check for 'Errors' -key returned by B2STAGE
    # since we made a HEAD request which has no body
    if not resp.status_code == 200:
        return None

    return url + '?access_token=' + b2stage_jwt

def _get_jwt_token(b2stage_url, payload={'username':'anonymous'}):
    b2safeproxy_endpoint = '/auth/b2safeproxy'
    url = b2stage_url + b2safeproxy_endpoint
    resp = requests.post(url, data=payload)

    if not resp.status_code == 200:
        return None

    b2stage_jwt = resp.json().get('Response', None).get('data', None).get('token', None)
    return b2stage_jwt
  
def _is_b2access_token_valid(b2access_token):
    b2access_url = current_app.extensions['invenio-oauthclient'].oauth.remote_apps['b2access'].base_url
    tokeninfo_endpoint = 'oauth2/tokeninfo'
    headers = {'Authorization': 'Bearer ' + b2access_token, 'Connection':'close', 'Cache-Control': 'no-cache'}
    url = b2access_url + tokeninfo_endpoint
    resp = requests.get(url, headers=headers)

    if not resp.status_code == 200:
        return False
    
    return True

class B2ShareFileStorage(PyFSFileStorage):
    """Class for B2Share file storage interface to files."""
    def send_file(self, filename, mimetype=None, restricted=True,
                  checksum=None, trusted=False, chunk_size=None):
        """Redirect to the actual pid of the file."""

        download_url = None
        b2stage_url = 'https://b2stage-test.cineca.it'
        # TODO: Implement a config variable to specify
        #       B2STAGE URL to use and it's endpoints.
        # NTS: Implement a config for list of trusted B2STAGE servers
        #      and check that PID resides in one them?
        # TODO: Refactor different steps into separate functions.
        
        # 1. Resolve
        # NTS: We only have access to handle.net URL
        handle_url = self.fileurl
        
        epic_pid = _get_epic_pid_from_handle_url(handle_url)

        # NTS: Not sure what Exceptions urllib.parse would give
        #      But let's still check for None
        if not epic_pid:
            abort(400, 'Invalid ePIC PID value')

        redirect_url = _resolve_redirect_url_of_epic_pid(epic_pid)
        
        if not redirect_url:
            abort(400, "ePIC PID couldn't be resolved, \
                        or it doesn't have a redirect URL")

        # 1.2 Check URI can be accessed with HTTP or HTTPS
        # NTS: Should other protocols be supported?
        if not _is_http_uri(redirect_url):
            abort(400, 'Invalid URI scheme for redirect:' + redirect_url)

        # 2. Check access with B2STAGE
        # TODO: Implement a config variable which turns B2STAGE resolving off.
        # TODO: Check if file can be accessed with B2STAGE
        # 'URL': 'https://b2stage-test.cineca.it/api/registered/cinecaDMPZone1/home/eudat/HelloUniverse.txt'
        # 'URL': 'irods://eirods-rzg.esc.rzg.mpg.de:1247/BasZone/home/julia/testcollection/collection_A/collection_A1/test1.txt'
        # NTS: Is there a faster way to check if file can be 
        #      fetched with B2STAGE than obtaining a JWT and 
        #      doing a HTTP HEAD with download=true param?

        # 2.2 Check if file can be accessed anonymously

        download_url = _check_file_access(b2stage_url, epic_pid)
        if not download_url:
            
            # TODO: Define a flag to turn reuse of B2ACCESS authentication off
            # 2.3 Check if current user is authorized to access the file

            # 2.3.1 Check that current_user is authenticated
            if not current_user.is_authenticated:
                abort(401, 'Authorization required for redirect')
            # TODO: Improve error message.
            # NTS: Should the user still be redirected to 
            #      redirect URL of the PID?
            #      Maybe there is a landing page where user can login?
        
            # 2.3.2 Obtain current_user's B2ACCESS token from db
            # NTS: Token refresh NOT implemented

            # Get B2ACCESS token of current_user
            oauth_remote = current_app.extensions['invenio-oauthclient'].oauth.remote_apps['b2access']
            b2access_token = token_getter(oauth_remote)
        
            if b2access_token is None:
                abort(401, 'Authorization required for redirect')
            # TODO: Change error message.
            # NTS: Should the user still be redirected to 
            #      redirect URL of the PID?
            #      Maybe there is a landing page where user can login?

            # 2.3.3 Check that B2ACCESS token for current_user is still valid
            if not _is_b2access_token_valid(b2access_token[0]):
                # TODO: Change error message.
                # NTS: Should user be asked to login again since
                #      B2ACCESS token refresh is not implemented?
                abort(401, 'Authorization required for redirect')
            
            # 2.3.4 Check if file can be accessed by current_user
            download_url = _check_file_access(b2stage_url, epic_pid, b2access_token[0], current_user.email)

            if not download_url:
                # TODO: Change error message.
                abort(401, 'Authorization required for redirect')

        # Add download=true so user will download the file
        # instead of obtaining metadata.
        download_url += '&download=true'

        # Return Redirect 307
        resp_headers = [('Location', download_url)]
        return make_response(("Found", 307, resp_headers))


def b2share_storage_factory(**kwargs):
    """Pass B2ShareFileStorage as parameter to pyfs_storage_factory."""
    if kwargs['fileinstance'].storage_class == 'B':
        kwargs['filestorage_class'] = B2ShareFileStorage
    return pyfs_storage_factory(**kwargs)
