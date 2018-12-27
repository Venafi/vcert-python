from .connection_cloud import CloudConnection
from .connection_tpp import TPPConnection
from .connection_fake import FakeConnection
from .common import CertificateRequest, CommonConnection


def Connection(url=None, token=None, user=None, password=None):
    """
    Return connection based on credentials list.
    TPP required url, user, password
    Cloud required token and optional url
    Fake required not parameters
    :param str url: TPP or cloud url (for cloud is optional)
    :param str token: cloud token
    :param str user: tpp user
    :param str password: tpp password
    :rtype CommonConnection:
    """
    if not (token or url or user or password):
        return FakeConnection()
    if url and user and password:
        return TPPConnection(user=user, password=password, url=url)
    if token:
        return CloudConnection(token=token, url=None)
    raise Exception("Bad credentials list")
