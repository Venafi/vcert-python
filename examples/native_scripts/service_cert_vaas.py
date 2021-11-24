#!/usr/bin/env python
import base64
import io
import logging
import random
import string
import zipfile
from os import environ

import requests
import six.moves.urllib.parse as urlparse
from nacl.encoding import Base64Encoder
from nacl.public import PublicKey, SealedBox

URL_APP_DETAILS = "{}/outagedetection/v1/applications/name/{}"
URL_CERT_REQUEST = "{}/outagedetection/v1/certificaterequests"
URL_DEK_HASH = "{}/outagedetection/v1/certificates/{}"
URL_DEK_PUBLIC_KEY = "{}/v1/edgeencryptionkeys/{}"
URL_CERT_KEYSTORE = "{}/outagedetection/v1/certificates/{}/keystore"
HTTP_STATUS_GOOD = (200, 201, 202)

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger("vaas-script")


def main():
    # VaaS credentials
    vaas_api_key = environ.get('VAAS_APIKEY')  # e.g. 'x2238x25-0689-4379-9xx9-x558872x4xxx'
    # VaaS required data
    vaas_endpoint = environ.get('VAAS_URL')  # e.g. 'https://api.venafi.cloud'
    # app_id = environ.get('VAAS_APP_ID')  # e.g. '5x8xx070-217x-11xx-9134-5x0x4xx5x8x8' # App Alfa
    # cit_id = environ.get('VAAS_CIT_ID')  # e.g. '0xx75x70-2181-11xx-xx0x-411653x7x9xx' # Both CIT
    app_name = environ.get('VAAS_APP_NAME')  # e.g. Open Source Integrations
    cit_alias = environ.get('VAAS_CIT_ALIAS')  # e.g. Unrestricted
    app_srv_type_id = '784938d1-ef0d-11eb-9461-7bb533ba575b'  # DO NOT CHANGE! Apache OOTB type
    domain = environ.get('VAAS_DOMAIN')  # e.g. "my.domain.xyz"
    private_key_password = environ.get('VAAS_PK_PASSWORD')  # r.g. b'newPassw0rd!'
    root_first = True

    # Headers to be used on api calls
    headers = {
        'accept': 'application/json',
        'content-type': 'application/json',
        'tppl-api-key': vaas_api_key
    }

    # Get the ids of the application and certificate issuing templates
    # App name must be escaped to be safely passed into the url
    escaped_app_name = urlparse.quote(app_name)
    uri = URL_APP_DETAILS.format(vaas_endpoint, escaped_app_name)
    r = requests.get(url=uri, headers=headers)
    if r.status_code not in HTTP_STATUS_GOOD:
        resp = get_http_response(r)
        log.error(msg="Error retrieving details from Application with name = {}\n"
                      "Escaped name = {}\n"
                      "Response: {}".format(app_name, escaped_app_name, resp))
        return

    app_id = r.json()['id']
    cit_alias_map = r.json()['certificateIssuingTemplateAliasIdMap']  # type: dict
    cit_id = cit_alias_map.get(cit_alias)
    if not cit_id:
        log.error(msg="Cit alias '{}' not found in Application with name {}".format(cit_alias, app_name))
        return

    # Request a new certificate using CKG
    name = random_word(16)
    common_name = "{}.{}".format(name, domain)
    body = {
        'isVaaSGenerated': True,
        'applicationId': app_id,
        'certificateIssuingTemplateId': cit_id,
        'applicationServerTypeId': app_srv_type_id,
        'validityPeriod': 'P7D',
        'csrAttributes': {
            'commonName': common_name,
            'organization': 'Venafi, Inc.',
            'organizationalUnits': [
                'Product Management'
            ],
            'locality': 'Salt Lake City',
            'state': 'Utah',
            'country': 'US',
            'subjectAlternativeNamesByType': {
                'dnsNames': [
                    common_name,
                ]
            }
        }
    }
    uri = URL_CERT_REQUEST.format(vaas_endpoint)
    r = requests.post(url=uri, headers=headers, json=body)
    if r.status_code not in HTTP_STATUS_GOOD:
        resp = get_http_response(r)
        log.error(msg="Error requesting certificate with CN = {}\n"
                      "Response: {}".format(common_name, resp))
        return

    # Get the certificate ID
    # There will always be one request and one certificate id
    certificate_id = r.json()["certificateRequests"][0]["certificateIds"][0]

    # Get dekHash of certificate using the certificate id
    # Required to obtain the DEK public key
    uri = URL_DEK_HASH.format(vaas_endpoint, certificate_id)
    r = requests.get(url=uri, headers=headers)
    if r.status_code not in HTTP_STATUS_GOOD:
        resp = get_http_response(r)
        log.error(msg="Error requesting DEK Hash for certificate with id = {}\n"
                      "Response: {}".format(certificate_id, resp))
        return

    # Get the dekHash
    dek_hash = r.json()["dekHash"]

    # Get the public key of DEK using the dekHash
    uri = URL_DEK_PUBLIC_KEY.format(vaas_endpoint, dek_hash)
    r = requests.get(url=uri, headers=headers)
    if r.status_code not in HTTP_STATUS_GOOD:
        resp = get_http_response(r)
        log.error(msg="Error requesting DEK Public Key for hash = {}\n"
                      "Response: {}".format(dek_hash, resp))
        return

    # Get the public key
    public_key_str = r.json()["key"]
    vaas_public_key = PublicKey(public_key_str, encoder=Base64Encoder)

    # Encrypt the key passphrase
    box = SealedBox(vaas_public_key)
    private_key_password_encrypted = box.encrypt(private_key_password)

    # Download the keystore and save it to a file
    # Add the octet-stream accept header
    headers['accept'] = 'application/octet-stream'
    body = {
        'exportFormat': 'PEM',
        'encryptedPrivateKeyPassphrase': base64.b64encode(private_key_password_encrypted).decode("utf-8"),
        'encryptedKeystorePassphrase': '',
        'certificateLabel': ''
    }
    uri = URL_CERT_KEYSTORE.format(vaas_endpoint, certificate_id)
    r = requests.post(url=uri, headers=headers, json=body)
    if r.status_code not in HTTP_STATUS_GOOD:
        resp = get_http_response(r)
        log.error(msg="Error downloading certificate keystore for certificate with id = {}\n"
                      "Response: {}".format(certificate_id, resp))
        return

    # The keystore is downloaded as a zip file
    # Extract certificate, private key, and chain from zip
    zip_data = r.content
    certificate, chain, private_key = extract_zip_files(zip_data, root_first)
    # Print the certificate, private key and  chain
    log.info("Success!!!")
    log.info("Certificate:\n{}".format(certificate))
    log.info("Private Key:\n{}".format(private_key))
    log.info("Full Chain:\n{}".format(chain))

    return


def get_http_response(response):
    """

    :param requests.Response response:
    :rtype: str
    """
    header = response.headers.get('Content-Type')
    if header == 'application/json':
        return response.json()
    elif header == 'text/plain':
        return response.text
    else:
        return response.content


def random_word(length):
    letters = string.ascii_lowercase + string.digits
    return ''.join(random.choice(letters) for _ in range(length))


def extract_zip_files(data, root_first):
    """

    :param data:
    :param bool root_first:
    :rtype: tuple[str, str, str]
    """
    zip_data = zipfile.ZipFile(io.BytesIO(data))
    private_key = None
    all_certs = []
    chain = None
    certificate = None
    # Iterate the zip files looking for the private key and the full-chain
    for info in zip_data.infolist():
        # Private key found
        if info.filename.endswith('.key'):
            f = zip_data.open(info)
            private_key = f.read().decode("utf-8").strip()
            f.close()
        # This file is used because the position of the certificates is fixed:
        # [0] -> root cert
        # [1] -> intermediate cert
        # [2] -> our certificate
        elif info.filename.endswith('_root-first.pem'):
            f = zip_data.open(info)
            all_certs = f.read().decode("utf-8").strip().split('\n\n')
            f.close()

    #
    if all_certs:
        for i in range(len(all_certs)):
            if i < len(all_certs) - 1:
                if not chain:
                    chain = all_certs[i]
                else:
                    val1 = chain if root_first else all_certs[i]
                    val2 = all_certs[i] if root_first else chain
                    chain = "{}\n{}".format(val1, val2)
                    # if root_first:
                    #     chain = "{}\n{}".format(chain, all_certs[i])
                    # else:
                    #     chain = "{}\n{}".format()all_certs[i] + '\n' + chain
            # Last position is always the certificate
            else:
                certificate = all_certs[i]
    # Return the values
    return certificate, chain, private_key


if __name__ == '__main__':
    main()
