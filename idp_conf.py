from saml2 import BINDING_HTTP_REDIRECT
from saml2.saml import NAMEID_FORMAT_PERSISTENT

HOST = "localhost"
PORT = 9000
BASE = f"http://{HOST}:{PORT}"

CONFIG = {
    "entityid": f"{BASE}/idp.xml",
    "service": {
        "idp": {
            "endpoints": {
                "single_sign_on_service": [
                    (f"{BASE}/sso/redirect", BINDING_HTTP_REDIRECT),
                ],
                "single_logout_service": [
                    (f"{BASE}/slo/redirect", BINDING_HTTP_REDIRECT),
                ],
            },
            "subject_data": "./idp.subject",
            "name_id_format": [NAMEID_FORMAT_PERSISTENT],
        },
    },
    "metadata": {
        "local": ["sp.xml"],
    },
    "attribute_map_dir" : "./attributemaps",
    "organization": {
        "display_name": "Python SAML IdP",
        "name": "Python SAML IdP",
        "url": "https://www.example.org",
    },
    "contact_person": [
        {
            "contact_type": "technical",
            "given_name": "Tech",
            "sur_name": "Support",
            "email_address": "technical@example.org",
        }
    ],
    "xmlsec_binary": "/usr/bin/xmlsec1",
}

LDAP_SETTINGS = {
    "ldapuri": "ldaps://ldap.example.org",
    "base": "uid={},ou=People,dc=de",
    "user_attrs": ("uid", "cn", "sn", "givenName", "mail"),
}
