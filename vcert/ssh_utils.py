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
import re

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


from .errors import ClientBadData, ServerUnexptedBehavior

PATH_SEPARATOR = "\\"
CA_ROOT_PATH = PATH_SEPARATOR + "VED" + PATH_SEPARATOR + "Certificate Authority" + PATH_SEPARATOR + "SSH" \
               + PATH_SEPARATOR + "Templates"
DEFAULT_SSH_KEY_SIZE = 3072
F_P_DETAILS = 'ProcessingDetails'


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
        self.status = None
        self.status_description = None
        p_details = response[F_P_DETAILS]
        if p_details:
            self.status = p_details['Status']  # type: str
            self.status_description = p_details['StatusDescription']  # type: str
        if not self.status:
            raise ServerUnexptedBehavior("Unknown response status. Status field not found")

        self.dn = response['DN'] if 'DN' in response else None  # type: str
        self.guid = response['Guid'] if 'Guid' in response else None  # type: str


class SSHRetrieveResponse:
    def __init__(self, response):
        """

        :param dict response:
        """
        self.status = None
        self.status_description = None
        p_details = response[F_P_DETAILS]
        if p_details:
            self.status = p_details['Status']  # type: str
            self.status_description = p_details['StatusDescription']  # type: str
        if not self.status:
            raise ServerUnexptedBehavior("Unknown response status. Status field not found")

        self.guid = response['Guid'] if 'Guid' in response else None  # type: str
        self.dn = response['DN'] if 'DN' in response else None  # type: str
        self.certificate_data = response['CertificateData'] if 'CertificateData' in response else None  # type: str
        self.private_key_data = response['PrivateKeyData'] if 'PrivateKeyData' in response else None  # type: str
        self.public_key_data = response['PublicKeyData'] if 'PublicKeyData' in response else None  # type: str
        self.ca_guid = response['CAGuid'] if "CAGuid" in response else None  # type: str
        self.ca_dn = response['CADN'] if 'CADN' in response else None  # type: str
        self.certificate_details = SSHCertDetails(response['CertificateDetails']) if 'CertificateDetails' in response \
            else None  # type: SSHCertDetails


class SSHCertDetails:
    def __init__(self, data):
        """

        :param dict data:
        """
        self.key_type = data['KeyType'] if 'KeyType' in data else None  # type: str
        self.cert_type = data['CertificateType'] if 'CertificateType' in data else None  # type: str
        self.cert_fingerprint_sha256 = data['CertificateFingerprintSHA256'] if 'CertificateFingerprintSHA256' in data \
            else None  # type: str
        self.ca_fingerprint_sha256 = data['CAFingerprintSHA256'] if 'CAFingerprintSHA256' in data else None  # type: str
        self.key_id = data['KeyID'] if 'KeyID' in data else None  # type: str
        self.serial_number = data['SerialNumber'] if 'SerialNumber' in data else None  # type: str
        self.principals = data['Principals'] if 'Principals' in data else None  # type: list[str]
        self.valid_from = data['ValidFrom'] if 'ValidFrom' in data else None  # type: int
        self.valid_to = data['ValidTo'] if 'ValidTo' in data else None  # type: int
        self.force_command = data['ForceCommand'] if 'ForceCommand' in data else None  # type: str
        self.source_addresses = data['SourceAddresses'] if 'SourceAddresses' in data else None  # type: list[str]
        self.public_key_fingerprint_sha256 = data['PublicKeyFingerprintSHA256'] \
            if 'PublicKeyFingerprintSHA256' in data else None  # type: str
        self.extensions = data['Extensions'] if 'Extensions' in data else None  # type: dict[str, Any]


class SSHResponse:
    def __init__(self, response):
        """

        :param dict response:
        """
        self.success = response['Success'] if 'Success' in response else None  # type: bool
        self.error_code = response['ErrorCode'] if 'ErrorCode' in response else None  # type: int
        self.error_msg = response['ErrorMessage'] if 'ErrorMessage' in response else None  # type: str


class SSHCATemplateRequest:
    def __init__(self, ca_template, ca_guid):
        """

        :param str ca_template:
        :param str ca_guid:
        """
        self.template = ca_template
        self.guid = ca_guid


class SSHTPPCADetails:
    def __init__(self, data):
        """

        :param dict data:
        """
        # TODO: Right now we are just extracting the necessary data from the response.
        #  If more details are required, extract them here.
        self.access_control = SSHAccessControl(data['AccessControl']) if 'AccessControl' in data \
            else None  # type: SSHAccessControl


class SSHAccessControl:
    def __init__(self, data):
        """

        :param dict data:
        """
        # TODO: Right now we are just extracting the necessary data from the response.
        #  If more details are required, extract them here.
        self.default_principals = data['DefaultPrincipals'] if 'DefaultPrincipals' in data else None  # type: dict


class SSHConfig:
    def __init__(self, ca_public_key=None, ca_principals=None):
        """

        :param str ca_public_key:
        :param list[str] ca_principals:
        """
        self.ca_public_key = ca_public_key
        self.ca_principals = ca_principals


class SSHKeyPair:
    def __init__(self):
        self._private_key = None  # type: str
        self._public_key = None  # type: str

    def generate(self, key_size=DEFAULT_SSH_KEY_SIZE, passphrase=None):
        """
        Generates a key pair (private, public) for use with SSH
        :param int key_size:
        :param str passphrase:
        :return:
        """
        if passphrase:
            encryption = serialization.BestAvailableEncryption(passphrase.encode())
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
        self._private_key = private_key.decode()
        self._public_key = public_key.decode()

    def private_key(self):
        return self._private_key

    def public_key(self):
        return self._public_key


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
        data['CADN'] = full_cadn

    if request.policy_dn:
        data['PolicyDN'] = request.policy_dn
    if request.object_name:
        data['ObjectName'] = request.object_name
    if request.destination_addresses:
        data['DestinationAddresses'] = request.destination_addresses
    if request.key_id:
        data['KeyId'] = request.key_id
    if request.principals:
        data['Principals'] = request.principals
    if request.validity_period:
        data['ValidityPeriod'] = request.validity_period
    if request.get_public_key_data():
        data['PublicKeyData'] = request.get_public_key_data()
    if request.extensions:
        data['Extensions'] = request.extensions
    if request.force_command:
        data['ForceCommand'] = request.force_command
    if request.source_addresses:
        data['SourceAddresses'] = request.source_addresses

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
        data['DN'] = request.pickup_id
    if request.guid:
        data['Guid'] = request.guid
    if request.private_key_passphrase:
        data['PrivateKeyPassphrase'] = request.private_key_passphrase

    data['IncludePrivateKeyData'] = True
    data['IncludeCertificateDetails'] = True

    return data


def write_ssh_files(file_path, file_name, certificate_data, private_key=None, public_key=None, for_windows=False):
    """

    :param str file_path:
    :param str file_name:
    :param str certificate_data:
    :param str private_key:
    :param  str public_key:
    :param bool for_windows:
    :rtype: None
    """
    if not file_path.endswith("/"):
        file_path += "/"
    normalized_name = re.sub(r"[^A-Za-z0-9]+", "_", file_name)
    full_path = file_path + normalized_name

    with open(full_path + "-cert.pub", "w") as cert_file:
        cert_file.write(certificate_data)

    if private_key:
        if not for_windows:
            private_key = private_key.replace("\r\n", "\n")
        with open(full_path, "w") as private_key_file:
            private_key_file.write(private_key)

    if public_key:
        with open(full_path + ".pub", "w") as public_key_file:
            public_key_file.write(public_key)
