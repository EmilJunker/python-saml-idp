# Python SAML Identity Provider

A simple SAML Identity Provider implemented in Python. Based on [Flask](https://github.com/pallets/flask), [PySAML2](https://github.com/IdentityPython/pysaml2), and [python-ldap](https://github.com/python-ldap/python-ldap).

This web application provides a simple SAML 2.0 based authentication flow. It connects to an LDAP server to look up the user information and verify the passwords. Any user who has an account in the LDAP can log in via this Identity Provider.

<img src="https://user-images.githubusercontent.com/19289477/170985376-60295556-7895-4a81-8e5f-d15427c7e985.png" alt="Login Form" width="360"> <img src="https://user-images.githubusercontent.com/19289477/170985544-90da92d1-7bd8-433e-84f6-76ba51467fdf.png" alt="Login Form" width="360">

## Prerequisites

- Git
- Python
- The packages listed in `.devcontainer/requirements.txt`

## Usage

1. Clone the repository:

```sh
git clone https://github.com/EmilJunker/python-saml-idp.git
cd python-saml-idp
```

2. Create a file `sp.xml` with the SAML 2.0 Metadata of your Service Provider in XML format. It should look something like this:

```xml
<md:EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://www.example.org/auth/realms/sp" ID="ID_898c42cd-2f41-423a-942c-e01cbcd64c2a">
<md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" AuthnRequestsSigned="false" WantAssertionsSigned="false">
<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://www.example.org/auth/realms/sp/broker/saml/endpoint"/>
<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://www.example.org/auth/realms/sp/broker/saml/endpoint" isDefault="true" index="1"/>
</md:SPSSODescriptor>
</md:EntityDescriptor>
```

3. Configure the Identity Provider using the file `idp_conf.py`. In particular, make sure the `LDAP_SETTINGS` match the configuration of the LDAP you want to connect to. If you plan to deploy the IdP behind a proxy, set the `BASE` to the public URL where the IdP will be reachable.

4. Next, generate an IdP metadata file based on the configuration:

```sh
make_metadata.py idp_conf.py > idp.xml
```

5. Finally, start the application:

```sh
./idp.py
```

## License

Distributed under the MIT License. See [LICENSE.txt](https://github.com/EmilJunker/python-saml-idp/blob/main/LICENSE.txt) for more information.

## Donations

If you find this project useful and would like to support me so I can dedicate more time to open source projects like this, here is my [PayPal link](https://www.paypal.me/EmilJunker) - Thanks!
