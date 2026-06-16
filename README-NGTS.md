[![Apache 2.0 License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
![Community Supported](https://img.shields.io/badge/Support%20Level-Community-brightgreen)
![Compatible with Palo Alto NGTS](https://img.shields.io/badge/Compatibility-Palo_Alto_NGTS-f9a90c)

_**This open source project is community-supported.** To report a problem or share an idea, use
**[Issues](https://github.com/Venafi/vcert-python/issues)**; and if you have a suggestion for fixing the issue, please include those details, too.
In addition, use **[Pull Requests](https://github.com/Venafi/vcert-python/pulls)** to contribute actual bug fixes or proposed enhancements.
We welcome and appreciate all contributions. Got questions or want to discuss something with our team?
**[Join us on Slack](https://join.slack.com/t/venafi-integrations/shared_invite/zt-i8fwc379-kDJlmzU8OiIQOJFSwiA~dg)**!_

# VCert Python SDK for Palo Alto Networks Next-Gen Trust Security (NGTS)

VCert Python is a library and SDK designed to simplify key generation and certificate
enrollment. This guide covers using it against **Palo Alto Networks Next-Gen Trust Security
(NGTS)**, also known as Strata Cloud Manager.

> 📌 **NOTE:** Unlike the [Go VCert](https://github.com/Venafi/vcert) project, vcert-python is
> **SDK-only** — there is no CLI, playbook, or certificate provisioning. NGTS support in this
> SDK is **certificate-lifecycle only**: `get_policy`/`set_policy`, SSH, and `get_version`
> raise `NotImplementedError`.

## Quick Links

- [Prerequisites](#prerequisites)
- [Connecting](#connecting)
  - [Connection Parameters](#connection-parameters)
  - [API URL Default and Token URL](#api-url-default-and-token-url)
- [Zone Format](#zone-format)
- [Examples](#examples)
  - [Connect with service-account credentials](#connect-with-service-account-credentials)
  - [Connect with a pre-issued access token](#connect-with-a-pre-issued-access-token)
  - [Request and retrieve a certificate](#request-and-retrieve-a-certificate)
  - [Renew a certificate](#renew-a-certificate)

## Prerequisites

1. The Palo Alto Networks NGTS API is reachable from where your code runs. The production
   endpoint is `https://api.strata.paloaltonetworks.com/ngts`.
2. A Palo Alto Networks NGTS service account has been registered and granted the permissions
   needed for the operations you use. See the
   [Palo Alto Networks service account documentation](https://pan.dev/scm/docs/service-accounts/).
   Minimum permissions per SDK operation:

   | SDK operation | Required NGTS permissions |
   |---|---|
   | `request_cert` (enroll) | `ngts.certificate_issuing_template.get`, `ngts.certificate_request.create`, `ngts.certificate_request.get`, `ngts.certificate_content.get` |
   | `retrieve_cert` (pickup) | `ngts.certificate_request.get`, `ngts.certificate.get`, `ngts.edge_encryption_key.get`, `ngts.certificate_content.get` |
   | `renew_cert` | `ngts.certificate.search`, `ngts.certificate_content.get`, `ngts.certificate_request.get`, `ngts.certificate.get`, `ngts.certificate_request.create` |
   | `revoke_cert` | _(see your NGTS CA Account configuration)_ |
   | `retire_cert` | `ngts.certificate.search`, `ngts.certificate_request.get`, `ngts.certificate.retire` |

3. You have **either** an OAuth access token, **or** service-account credentials (Client ID,
   Client Secret, and a TSG ID or scope) the SDK can use to obtain one.
4. A CA Account and an Issuing Template (CIT) exist and are configured with Recommended
   Settings (OU, O, L, ST, C) and appropriate Issuing Rules. You know the Issuing Template's
   **API alias**.

## Connecting

Use `venafi_connection`. NGTS is selected either explicitly via
`platform=VenafiPlatform.NGTS`, or automatically when `client_id` and `client_secret` are
supplied (these are NGTS-specific, so they aren't shadowed by the TPP/Cloud branches).

```python
from vcert import venafi_connection, VenafiPlatform

# Explicit platform selection (token_url defaults to production; override for non-prod)
conn = venafi_connection(
    platform=VenafiPlatform.NGTS,
    client_id="<service account client id>",
    client_secret="<service account client secret>",
    tsg_id="<tenant service group id>",
)

# Auto-detection (client_id + client_secret present)
conn = venafi_connection(
    client_id="<service account client id>",
    client_secret="<service account client secret>",
    tsg_id="<tenant service group id>",
)
```

### Connection Parameters

| Parameter | Required | Description |
|---|---|---|
| `client_id` | yes¹ | Service-account Client ID used to obtain an access token. |
| `client_secret` | yes¹ | Service-account Client Secret used to obtain an access token. |
| `tsg_id` | yes² | Tenant Service Group ID. Used to derive the OAuth scope as `tsg_id:<TSG_ID>`. |
| `scope` | yes² | OAuth scope (e.g. `tsg_id:<TSG_ID>`). Takes precedence over `tsg_id` when supplied. |
| `access_token` | no¹ | A pre-issued OAuth access token. When supplied, `client_id`/`client_secret` become optional (but are still used to refresh the token if present). |
| `token_url` | no | OAuth token endpoint. Defaults to the Palo Alto production endpoint (see below); override it for non-production environments. |
| `url` | no | NGTS API base URL. Defaults to the Palo Alto production endpoint (see below). |
| `http_request_kwargs` | no | Passed through to `requests` (e.g. a trust bundle via `verify`). |

¹ Provide **either** `access_token`, **or** `client_id` + `client_secret`.
² Provide **either** `scope`, **or** `tsg_id` (used to derive the scope).

### API URL and Token URL Defaults

Both `url` (API base URL) and `token_url` (OAuth token endpoint) are optional. When omitted
they default to the published Palo Alto **production** endpoints — supply them only for
non-production environments:

| Parameter | Default |
|---|---|
| `url` | `https://api.strata.paloaltonetworks.com/ngts` |
| `token_url` | `https://auth.apps.paloaltonetworks.com/auth/v1/oauth2/access_token` |

The production token endpoint is taken from the Palo Alto SASE auth API
([reference](https://pan.dev/sase/api/auth/post-auth-v-1-oauth-2-access-token/)).

> **Note:** Defaulting `token_url` is a deliberate divergence from the Go VCert
> implementation, which still requires the token URL. It is a planned-but-not-yet-upstreamed
> change.

#### Safeguards around `token_url`

`token_url` is the **credential sink** — your service-account `client_id`/`client_secret` are
exchanged there via HTTP Basic auth — so the SDK guards it without giving up the default:

- **HTTPS is enforced.** An `http://` `token_url` is upgraded to `https://` (with a warning) and
  a scheme-less value is assumed to be `https://`, so credentials never travel in cleartext.
- **Defaulting is logged.** Omitting `token_url` logs a **WARNING** before falling back to the
  production endpoint. This is intentional: if you target a **non-production** tenant but forget to
  set `token_url`, your non-prod credentials would otherwise be sent to the **production** token
  endpoint silently. Always set `token_url` explicitly for non-production.
- **Untrusted hosts are flagged.** A `token_url` whose host is outside `.paloaltonetworks.com`
  (which covers both production and the documented dev endpoints) logs a **WARNING**, surfacing a
  typo'd or hostile endpoint that would leak credentials.

The last two **warn rather than block**, so a future legitimate endpoint on another domain still
works — but you should treat these warnings as a prompt to double-check your configuration.

## Zone Format

For NGTS, the **zone is the Issuing Template (CIT) API alias only**. There is no
`Application\IssuingTemplate` split as there is for CyberArk Certificate Manager, SaaS — the
entire string (trimmed) is the template alias, and a backslash is part of the alias, not a
separator.

```python
zone = "PublicTrust"   # the Issuing Template API alias
```

## Examples

For the examples below, assume the Issuing Template has an API alias of `PublicTrust`.

### Connect with service-account credentials

```python
from vcert import venafi_connection, VenafiPlatform

conn = venafi_connection(
    platform=VenafiPlatform.NGTS,
    token_url="<oauth token endpoint>",
    client_id="<client id>",
    client_secret="<client secret>",
    tsg_id="<tsg id>",
)
```

### Connect with a pre-issued access token

```python
from vcert import venafi_connection, VenafiPlatform

conn = venafi_connection(
    platform=VenafiPlatform.NGTS,
    access_token="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
)
```

### Request and retrieve a certificate

```python
from vcert import CertificateRequest

zone = "PublicTrust"
request = CertificateRequest(common_name="first-time.venafi.example")
request.san_dns = ["first-san.venafi.example", "second-san.venafi.example"]

conn.request_cert(request, zone)
cert = conn.retrieve_cert(request)   # polls until the certificate is issued

print(cert.cert)    # end-entity certificate (PEM)
print(cert.chain)   # chain certificates (PEM)
print(request.private_key_pem)
```

### Renew a certificate

```python
from vcert import CertificateRequest

# Renew by the enrollment (pickup) id of the existing certificate
request = CertificateRequest(cert_id="{7428fac3-d0e8-4679-9f48-d9e867a326ca}")
conn.renew_cert(request)
cert = conn.retrieve_cert(request)
```

---

For backend-neutral SDK usage (request/retrieve/renew/revoke data objects, output formats),
see the main [README](README.md).
