class VenafiError(Exception):
    pass


class VenafiConnectionError(VenafiError):
    pass


class ServerUnexptedBehavior(VenafiError):
    pass


class BadData(VenafiError):
    pass


class ClientBadData(BadData):
    pass


class CertificateRequestError(ServerUnexptedBehavior):
    pass


class CertificateRenewError(ServerUnexptedBehavior):
    pass


class AuthenticationError(VenafiError):
    pass
