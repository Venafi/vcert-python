from __future__ import (absolute_import, division, generators, unicode_literals, print_function, nested_scopes,
                        with_statement)

import base64
import logging as log
import re
import time

import requests

from .common import CommonConnection, MIME_JSON
from .errors import (ServerUnexptedBehavior, ClientBadData, CertificateRequestError, AuthenticationError,
                     CertificateRenewError)
from .http import HTTPStatus


class URLS:
    API_BASE_URL = ""

    AUTHORIZE = "authorize/"
    CERTIFICATE_REQUESTS = "certificates/request"
    CERTIFICATE_RETRIEVE = "certificates/retrieve"
    FIND_POLICY = "config/findpolicy"
    CERTIFICATE_REVOKE = "certificates/revoke"
    CERTIFICATE_RENEW = "certificates/renew"
    CERTIFICATE_SEARCH = "certificates/"
    CERTIFICATE_IMPORT = "certificates/import"


TOKEN_HEADER_NAME = "x-venafi-api-key"


class TPPConnection(CommonConnection):
    def __init__(self, user, password, url):
        """
        todo: docs
        :param str user:
        :param str password:
        :param str url:
        """
        self._base_url = url  # type: str
        self._user = user  # type: str
        self._password = password  # type: str
        self._token = None  # type: tuple
        self._normalize_and_verify_base_url()

    def _get(self, url="", params=None):
        if not self._token or self._token[1] < time.time() + 1:
            self.auth()
            log.debug("Token is %s, timeout is %s" % (self._token[0], self._token[1]))

        r = requests.get(self._base_url + url, headers={TOKEN_HEADER_NAME: self._token[0], 'content-type':
                         MIME_JSON, 'cache-control': 'no-cache'}, params=params, verify=False)
        return self.process_server_response(r)

    def _post(self, url, data=None):
        if not self._token or self._token[1] < time.time() + 1:
            self.auth()
            log.debug("Token is %s, timeout is %s" % (self._token[0], self._token[1]))

        if isinstance(data, dict):
            r = requests.post(self._base_url + url, headers={TOKEN_HEADER_NAME: self._token[0], 'content-type':
                              MIME_JSON, "cache-control": "no-cache"}, json=data, verify=False)
        else:
            log.error("Unexpected client data type: %s for %s" % (type(data), url))
            raise ClientBadData
        return self.process_server_response(r)

    def _get_cert_status(self, request):
        status, data = self._post(URLS.CERTIFICATE_RETRIEVE % request.id)
        if status == HTTPStatus.OK:
            return data

    def _normalize_and_verify_base_url(self):
        u = self._base_url
        if u.startswith("http://"):
            u = "https://" + u[7:]
        elif not u.startswith("https://"):
            u = "https://" + u
        if not u.endswith("/"):
            u += "/"
        if not u.endswith("vedsdk/"):
            u += "vedsdk/"
        if not re.match(r"^https://[a-z\d]+[-a-z\d.]+[a-z\d][:\d]*/vedsdk/$", u):
            raise ClientBadData
        self._base_url = u

    def ping(self):
        status, data = self._get()
        return status == HTTPStatus.OK and "Ready" in data

    def auth(self):
        data = {"Username": self._user, "Password": self._password}

        #TODO: add trust bundle support and remove verify=False
        r = requests.post(self._base_url + URLS.AUTHORIZE, json=data,
                          headers={'content-type': MIME_JSON, "cache-control": "no-cache"}, verify=False)

        status, user = self.process_server_response(r)
        if status == HTTPStatus.OK:
            valid_until = int(re.sub(r"\D", "", user["ValidUntil"]))
            self._token = user["APIKey"], valid_until
            return user
        else:
            log.error("Authentication status is not %s but %s. Exiting" % (HTTPStatus.OK, status[0]))
            raise AuthenticationError

    # TODO: Need to add service genmerated CSR implementation
    def request_cert(self, request, zone):
        if not request.csr:
            request.build_csr()
        status, data = self._post(URLS.CERTIFICATE_REQUESTS,
                                  data={"PolicyDN": self._get_policy_dn(zone),
                                        "PKCS10": request.csr,
                                        "ObjectName": request.friendly_name,
                                        "DisableAutomaticRenewal": "true"})
        if status == HTTPStatus.OK:
            request.id = data['CertificateDN']
            log.debug("Certificate sucessfully requested with request id %s." % request.id)
            return True
        else:
            log.error("Request status is not %s. %s." % HTTPStatus.OK, status)
            raise CertificateRequestError

    def retrieve_cert(self, certificate_request):
        log.debug("Getting certificate status for id %s" % certificate_request.id)

        retrive_request = dict(CertificateDN=certificate_request.id, Format="base64", IncludeChain='true')

        if certificate_request.chain_option == "last":
            retrive_request['RootFirstOrder'] = 'false'
            retrive_request['IncludeChain'] = 'true'
        elif certificate_request.chain_option == "first":
            retrive_request['RootFirstOrder'] = 'true'
            retrive_request['IncludeChain'] = 'true'
        else:
            retrive_request['IncludeChain'] = 'false'

        status, data = self._post(URLS.CERTIFICATE_RETRIEVE, data=retrive_request)
        if status == HTTPStatus.OK:
            pem64 = data['CertificateData']
            pem = base64.b64decode(pem64)
            return pem.decode()
        elif status == HTTPStatus.ACCEPTED:
            log.debug(data['Status'])
            return None
        else:
            log.error("Status is not %s. %s" % HTTPStatus.OK, status)
            raise ServerUnexptedBehavior

    def revoke_cert(self, request):
        raise NotImplementedError

    def renew_cert(self, request):
        if not request.id:
            log.debug("Request id must be specified for TPP")
            raise CertificateRenewError
        log.debug("Trying to renew certificate %s" % request.id)
        status, data = self._post(URLS.CERTIFICATE_RENEW, data={"CertificateDN": request.id})
        if not data['Success']:
            raise CertificateRenewError

    def read_zone_conf(self, tag):
        raise NotImplementedError

    def import_cert(self, request):
        raise NotImplementedError

    @staticmethod
    def _get_policy_dn(zone):
        if re.match(r"^\\\\VED\\\\Policy", zone):
            return zone
        else:
            if re.match(r"^\\\\", zone):
                return r"\\VED\\Policy" + zone
            else:
                return r"\\VED\\Policy\\" + zone
