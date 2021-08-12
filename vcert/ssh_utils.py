#
# Copyright 2016 Python Software Foundation
#
# Licensed under the Python Software Foundation License (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  https://docs.python.org/3/license.html
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


from errors import ClientBadData

PATH_SEPARATOR = "\\"
CA_ROOT_PATH = PATH_SEPARATOR + "VED" + PATH_SEPARATOR + "Certificate Authority" + PATH_SEPARATOR + "SSH" \
               + PATH_SEPARATOR + "Templates"
DEFAULT_SSH_KEY_SIZE = 3072


class SSHCertRequest:
    def __init__(self, cadn, key_id, validity_period=None, policy_dn=None, object_name=None, destination_addresses=None,
                 principals=None, public_key_data=None, extensions=None, force_command=None,
                 source_addresses=None, pickup_id=None, guid=None, include_priv_key_data=False,
                 priv_key_passphrase=None, priv_key_format=None, include_cert_details=False, timeout=180
                 ):
        """
        :param str cadn:
        :param str key_id:
        :param str validity_period:
        :param str policy_dn:
        :param str object_name:
        :param list destination_addresses:
        :param list principals:
        :param str public_key_data:
        :param list extensions:
        :param str force_command:
        :param list source_addresses:
        :param str pickup_id:
        :param str guid:
        :param bool include_priv_key_data:
        :param str priv_key_passphrase:
        :param str priv_key_format:
        :param bool include_cert_details:
        :param int timeout:
        """
        # Fields for the request of the certificate
        self.cadn = cadn
        self.key_id = key_id
        self.validity_period = validity_period
        self.policy_dn = policy_dn
        self.object_name = object_name
        self.destination_addresses = destination_addresses
        self.principals = principals
        self._public_key_data = public_key_data
        self.extensions = extensions
        self.force_command = force_command
        self.source_addresses = source_addresses

        # Fields for the retrieval of the certificate
        self.pickup_id = pickup_id
        self.guid = guid
        self.include_private_key_data = include_priv_key_data
        self.private_key_passphrase = priv_key_passphrase
        self.private_key_format = priv_key_format
        self.include_cert_details = include_cert_details
        self.timeout = timeout

    def get_public_key_data(self):
        """
        :rtype: str
        """
        if not self._public_key_data:
            return None
        temp = self._public_key_data.rstrip("\r\n")
        if self.key_id:
            return "%s %s" % (temp, self.key_id)
        else:
            return temp

    def set_public_key_data(self, key):
        """

        :param str key:
        :rtype: None
        """
        self._public_key_data = key


class SSHCertResponse:
    def __init__(self, response):
        """
        :param dict response:
        """

        self.dn = response["DN"] if "DN" in response else None
        self.guid = response["Guid"] if "Guid" in response else None
        self.status = response["Status"] if "Status" in response else None

        resp = response["Response"] if "Response" in response else dict()
        self.response = SSHResponse(resp)


class SSHRetrieveResponse:
    def __init__(self, response):
        """

        :param dict response:
        """
        self.status = response["Status"] if "Status" in response else None  # type: str
        self.guid = response["Guid"] if "Guid" in response else None  # type: str
        self.dn = response["DN"] if "DN" in response else None  # type: str
        self.cert_data = response["CertificateData"] if "CertificateData" in response else None  # type: str
        self.private_key_data = response["PrivateKeyData"] if "PrivateKeyData" in response else None  # type: str
        self.public_key_data = response["PublicKeyData"] if "PublicKeyData" in response else None  # type: str
        self.ca_guid = response["CAGuid"] if "CAGuid" in response else None  # type: str
        self.ca_dn = response["CADN"] if "CADN" in response else None  # type: str
        self.cert_details = SSHCertDetails(response["CertificateDetails"]) if "CertificateDetails" in response else None
        # type: SSHCertDetails


class SSHCertDetails:
    def __init__(self, data):
        """

        :param dict data:
        """
        self.key_type = data["KeyType"] if "" in data else None
        self.cert_type = data["CertificateType"] if "CertificateType" in data else None
        self.cert_fingerprint_sha256 = data["CertificateFingerprintSHA256"] if "CertificateFingerprintSHA256" in data \
            else None
        self.ca_fingerprint_sha256 = data["CAFingerprintSHA256"] if "CAFingerprintSHA256" in data else None
        self.key_id = data["KeyID"] if "KeyID" in data else None
        self.serial_number = data["SerialNumber"] if "SerialNumber" in data else None
        self.principals = data["Principals"] if "Principals" in data else None
        self.valid_from = data["ValidFrom"] if "ValidFrom" in data else None
        self.valid_to = data["ValidTo"] if "ValidTo" in data else None
        self.force_command = data["ForceCommand"] if "ForceCommand" in data else None
        self.source_addresses = data["SourceAddresses"] if "SourceAddresses" in data else None
        self.public_key_fingerprint_sha256 = data["PublicKeyFingerprintSHA256"] \
            if "PublicKeyFingerprintSHA256" in data else None
        self.extensions = data["Extensions"] if "Extensions" in data else None


class SSHResponse:
    def __init__(self, response):
        """

        :param dict response:
        """
        self.success = response["Success"] if "Success" in response else None
        self.error_code = response["ErrorCode"] if "ErrorCode" in response else None
        self.error_msg = response["ErrorMessage"] if "ErrorMessage" in response else None


class SSHKeyPair:
    def __init__(self, private, public):
        """

        :param str private:
        :param str public:
        """
        self.private_key = private
        self.public_key = public


def build_tpp_request(request):
    """
    :param SSHCertRequest request:
    :rtype: dict
    """
    if not request:
        raise ClientBadData("The SSH request is empty")

    data = dict()
    if request.cadn:
        full_cadn = request.cadn
        if not full_cadn.startswith(PATH_SEPARATOR):
            full_cadn = PATH_SEPARATOR + request.cadn
        if not full_cadn.startswith(CA_ROOT_PATH):
            full_cadn = CA_ROOT_PATH + full_cadn
        data["CADN"] = full_cadn

    if request.policy_dn:
        data["PolicyDN"] = request.policy_dn
    if request.object_name:
        data["ObjectName"] = request.object_name
    if request.destination_addresses:
        data["DestinationAddresses"] = request.destination_addresses
    if request.key_id:
        data["KeyId"] = request.key_id
    if request.principals:
        data["Principals"] = request.principals
    if request.validity_period:
        data["ValidityPeriod"] = request.validity_period
    if request.get_public_key_data():
        data["PublicKeyData"] = request.get_public_key_data()
    if request.extensions:
        data["Extensions"] = request.extensions
    if request.force_command:
        data["ForceCommand"] = request.force_command
    if request.source_addresses:
        data["SourceAddresses"] = request.source_addresses

    return data


def build_tpp_retrieve_request(request):
    """

    :param SSHCertRequest request:
    :rtype: dict
    """
    if not request:
        raise ClientBadData("The SSH request is empty")

    data = dict()
    if request.pickup_id:
        data["DN"] = request.pickup_id
    if request.guid:
        data["Guid"] = request.guid
    if request.private_key_passphrase:
        data["PrivateKeyPassphrase"] = request.private_key_passphrase

    data["IncludePrivateKeyData"] = True
    data["IncludeCertificateDetails"] = True

    return data


def generate_ssh_keypair(key_size=DEFAULT_SSH_KEY_SIZE, passphrase=None):
    """
    Generates a key pair (private, public) for use with SSH
    :param int key_size:
    :param str passphrase:
    :rtype: SSHKeyPair
    """
    if passphrase:
        encryption = serialization.BestAvailableEncryption(passphrase)
    else:
        encryption = serialization.NoEncryption()

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    private_key = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption)
    public_key = key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH
    )

    return SSHKeyPair(private_key, public_key)
