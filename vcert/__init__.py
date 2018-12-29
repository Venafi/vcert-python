from .connection_cloud import CloudConnection
from .connection_tpp import TPPConnection
from .connection_fake import FakeConnection
from .common import CertificateRequest, CommonConnection, KeyTypes


def Connection(url=None, token=None, user=None, password=None, ignore_ssl_errors=False):
    """
    Return connection based on credentials list.
    TPP required url, user, password
    Cloud required token and optional url
    Fake required not parameters
    :param str url: TPP or cloud url (for cloud is optional)
    :param str token: cloud token
    :param str user: tpp user
    :param str password: tpp password
    :param bool ignore_ssl_errors: Option for work with untrusted tpp https certificate (only for tpp).
    :rtype CommonConnection:
    """
    if not (token or url or user or password):
        return FakeConnection()
    if url and user and password:
        return TPPConnection(user=user, password=password, url=url, ignore_ssl_errors=ignore_ssl_errors)
    if token:
        return CloudConnection(token=token, url=None)
    raise Exception("Bad credentials list")
