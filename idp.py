#!/usr/bin/env python

import argparse
import base64
from hashlib import sha1
import importlib.util
import logging
import os
import six

from flask import Flask, Response, abort, redirect, render_template, request

import ldap

from saml2 import BINDING_HTTP_REDIRECT
from saml2 import server
from saml2.authn_context import AuthnBroker
from saml2.authn_context import PASSWORD
from saml2.authn_context import UNSPECIFIED
from saml2.authn_context import authn_context_class_ref
from saml2.config import config_factory
from saml2.metadata import create_metadata_string
from saml2.s_utils import UnknownPrincipal
from saml2.s_utils import UnsupportedBinding
from saml2.s_utils import exception_trace
from saml2.s_utils import rndstr
from saml2.sigver import encrypt_cert_from_item
from saml2.sigver import verify_redirect_signature


logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))


class Cache(object):
    def __init__(self):
        self.user2uid = {}
        self.uid2user = {}


# -----------------------------------------------------------------------------


class Service(object):
    def __init__(self, request, user=None):
        self.request = request
        logging.debug("REQUEST: %s", request)
        self.user = user

    def get_url_without_query(self):
        return CONFIG.BASE + self.request.environ.get("PATH_INFO", "")

    def unpack_redirect(self):
        args = self.request.args
        return args.to_dict(flat=True)

    def operation(self, saml_msg, binding):
        logging.debug("_operation: %s", saml_msg)
        if not (saml_msg and "SAMLRequest" in saml_msg):
            return abort(400, "Error parsing request or no request")
        else:
            # saml_msg may also contain Signature and SigAlg
            if "Signature" in saml_msg:
                try:
                    kwargs = {
                        "signature": saml_msg["Signature"],
                        "sigalg": saml_msg["SigAlg"],
                    }
                except KeyError:
                    return abort(400, "Signature Algorithm specification is missing")
            else:
                kwargs = {}

            try:
                kwargs["encrypt_cert"] = encrypt_cert_from_item(
                    saml_msg["req_info"].message
                )
            except KeyError:
                pass

            try:
                kwargs["relay_state"] = saml_msg["RelayState"]
            except KeyError:
                pass

            return self.do(saml_msg["SAMLRequest"], binding, **kwargs)

    def response(self, binding, http_args, cookie=None):
        resp = None
        if binding == BINDING_HTTP_REDIRECT:
            for key, value in http_args["headers"]:
                if key.lower() == "location":
                    resp = redirect(value)
        elif http_args["data"]:
            resp = Response(http_args["data"], headers=http_args["headers"])

        if not resp:
            return abort(400, "Don't know how to return response")

        if cookie:
            resp.set_cookie("idpauthn", **cookie)

        return resp

    def do(self, request, binding, relay_state="", encrypt_cert=None):
        """
        :param request: The request
        :param binding: Which binding was used when receiving the request
        :param relay_state: The relay state provided by the SP
        :param encrypt_cert: Cert to use for encryption
        :return: A response
        """
        pass

    def redirect(self):
        saml_msg = self.unpack_redirect()
        return self.operation(saml_msg, BINDING_HTTP_REDIRECT)

    def not_authn(self, requested_authn_context, key):
        redirect_uri = self.get_url_without_query()
        return do_authentication(requested_authn_context, key, redirect_uri)


# -----------------------------------------------------------------------------
# === Single log in ====
# -----------------------------------------------------------------------------


class SSO(Service):
    def __init__(self, request, user=None):
        Service.__init__(self, request, user)
        self.binding = ""
        self.response_bindings = None
        self.resp_args = {}
        self.binding_out = None
        self.destination = None
        self.req_info = None

    def verify_request(self, request, binding):
        resp_args = {}
        if not request:
            logging.error("Missing request query")
            return resp_args, abort(401, "Unknown user")

        if not self.req_info:
            self.req_info = IDP.parse_authn_request(request, binding)

        _authn_req = self.req_info.message

        try:
            self.binding_out, self.destination = IDP.pick_binding(
                "assertion_consumer_service",
                bindings=self.response_bindings,
                entity_id=_authn_req.issuer.text,
                request=_authn_req,
            )
        except Exception as err:
            logging.error("Couldn't find receiver endpoint: %s", err)
            raise

        logging.debug("Binding: %s, destination: %s", self.binding_out, self.destination)

        resp_args = {}
        try:
            resp_args = IDP.response_args(_authn_req)
            _resp = None
        except UnknownPrincipal as excp:
            _resp = IDP.create_error_response(_authn_req.id, self.destination, excp)
        except UnsupportedBinding as excp:
            _resp = IDP.create_error_response(_authn_req.id, self.destination, excp)

        return resp_args, _resp

    def do(self, request, binding, relay_state="", encrypt_cert=None):
        try:
            resp_args, _resp = self.verify_request(request, binding)
        except UnknownPrincipal as excp:
            logging.error("UnknownPrincipal: %s", excp)
            return abort(500, "Unknown Principal")
        except UnsupportedBinding as excp:
            logging.error("UnsupportedBinding: %s", excp)
            return abort(500, "Unsupported Binding")

        if not _resp:
            try:
                dn = CONFIG.LDAP_SETTINGS["base"].format(self.user)
                conn = ldap.initialize(CONFIG.LDAP_SETTINGS["ldapuri"])
                try:
                    attrs = CONFIG.LDAP_SETTINGS["user_attrs"]
                except KeyError:
                    attrs = None
                result = conn.search_s(dn, ldap.SCOPE_SUBTREE, attrlist=attrs)
                identity = result[0][1]
            except Exception as excp:
                logging.error(exception_trace(excp))
                return abort(500, "Internal Exception")
            logging.info("Identity: %s", identity)

            try:
                _resp = IDP.create_authn_response(
                    identity,
                    userid=self.user,
                    encrypt_cert_assertion=encrypt_cert,
                    **resp_args
                )
            except Exception as excp:
                logging.error(exception_trace(excp))
                return abort(500, "Internal Exception")

        logging.info("AuthnResponse: %s", _resp)
        kwargs = {}

        http_args = IDP.apply_binding(
            self.binding_out,
            "%s" % _resp,
            self.destination,
            relay_state,
            response=True,
            **kwargs
        )

        logging.debug("HTTPargs: %s", http_args)
        return self.response(self.binding_out, http_args)

    @staticmethod
    def _store_request(saml_msg):
        logging.debug("_store_request: %s", saml_msg)
        key = sha1(saml_msg["SAMLRequest"].encode()).hexdigest()
        # store the AuthnRequest
        IDP.ticket[key] = saml_msg
        return key

    def redirect(self):
        logging.info("--- In SSO Redirect ---")
        saml_msg = self.unpack_redirect()

        try:
            _key = saml_msg["key"]
            saml_msg = IDP.ticket[_key]
            self.req_info = saml_msg["req_info"]
            del IDP.ticket[_key]
        except KeyError:
            try:
                self.req_info = IDP.parse_authn_request(
                    saml_msg["SAMLRequest"], BINDING_HTTP_REDIRECT
                )
            except KeyError:
                return abort(400, "Message parsing failed")

            if not self.req_info:
                return abort(400, "Message parsing failed")

            _req = self.req_info.message

            if "SigAlg" in saml_msg and "Signature" in saml_msg:
                # Signed request
                issuer = _req.issuer.text
                _certs = IDP.metadata.certs(issuer, "any", "signing")
                verified_ok = False
                for cert_name, cert in _certs:
                    if verify_redirect_signature(saml_msg, IDP.sec.sec_backend, cert):
                        verified_ok = True
                        break
                if not verified_ok:
                    return abort(400, "Message signature verification failure")

            if self.user:
                saml_msg["req_info"] = self.req_info
                if _req.force_authn is not None and _req.force_authn.lower() == "true":
                    key = self._store_request(saml_msg)
                    return self.not_authn(_req.requested_authn_context, key)
                else:
                    return self.operation(saml_msg, BINDING_HTTP_REDIRECT)
            else:
                saml_msg["req_info"] = self.req_info
                key = self._store_request(saml_msg)
                return self.not_authn(_req.requested_authn_context, key)
        else:
            return self.operation(saml_msg, BINDING_HTTP_REDIRECT)


# -----------------------------------------------------------------------------
# === Authentication ====
# -----------------------------------------------------------------------------


def do_authentication(authn_context, key, redirect_uri):
    logging.debug("Do authentication")
    auth_info = AUTHN_BROKER.pick(authn_context)

    # Clear cookie if it already exists
    delcookie = delete_cookie()

    if len(auth_info):
        method, reference = auth_info[0]
        logging.debug("Authn chosen: %s (ref=%s)", method, reference)
        return method(reference, key, redirect_uri, delcookie)
    else:
        return abort(401, "No usable authentication method")


# -----------------------------------------------------------------------------


def username_password_authn(reference, key, redirect_uri, delcookie):
    login_form = render_template("login.html",
        static_dir=f"{CONFIG.BASE}/static",
        action=f"{CONFIG.BASE}/verify",
        login="",
        password="",
        key=key,
        authn_reference=reference,
        redirect_uri=redirect_uri
    )
    resp = Response(login_form)
    if delcookie:
        resp.set_cookie("idpauthn", **delcookie)
    return resp


def verify_username_and_password(dic):
    username = dic["login"]
    password = dic["password"]
    try:
        dn = CONFIG.LDAP_SETTINGS["base"].format(username)
        conn = ldap.initialize(CONFIG.LDAP_SETTINGS["ldapuri"])
        conn.simple_bind_s(dn, password)
        return True, username
    except Exception:
        return False, None


def do_verify(dic):
    try:
        ok, user = verify_username_and_password(dic)
    except KeyError:
        ok = False
        user = None

    if not ok:
        return render_template("error.html",
            static_dir=f"{CONFIG.BASE}/static",
            error_message="Unknown user or wrong password"
        )
    else:
        uid = rndstr(24)
        IDP.cache.uid2user[uid] = user
        IDP.cache.user2uid[user] = uid
        logging.debug("Register %s under '%s'", user, uid)

        key = dic.get("key")
        redirect_uri = dic.get("redirect_uri")
        redirect_uri += "?key=%s&id=%s" % (key, uid)
        logging.debug("Redirect => %s", redirect_uri)

        resp = redirect(redirect_uri)
        cookie = make_cookie(uid, dic.get("authn_reference"))
        resp.set_cookie("idpauthn", **cookie)

        return resp


# -----------------------------------------------------------------------------
# === Single log out ===
# -----------------------------------------------------------------------------


class SLO(Service):
    def do(self, request, binding, relay_state="", encrypt_cert=None):
        logging.info("--- Single Log Out Service ---")

        try:
            req_info = IDP.parse_logout_request(request, binding)
        except Exception as exc:
            logging.error("Bad request: %s", exc)
            return abort(400, "Bad request")

        _req = req_info.message

        if _req.name_id:
            lid = IDP.ident.find_local_id(_req.name_id)
            logging.info("local identifier: %s", lid)
            if lid in IDP.cache.user2uid:
                uid = IDP.cache.user2uid[lid]
                if uid in IDP.cache.uid2user:
                    del IDP.cache.uid2user[uid]
                del IDP.cache.user2uid[lid]
            # remove the authentication
            try:
                IDP.session_db.remove_authn_statements(_req.name_id)
            except KeyError as exc:
                logging.error("Unknown session: %s", exc)
                return abort(400, "Unknown session")

        resp = IDP.create_logout_response(_req, [binding])

        binding, destination = IDP.pick_binding(
            "single_logout_service", [binding], "spsso", req_info
        )

        try:
            http_args = IDP.apply_binding(
                binding, "%s" % resp, destination, relay_state, response=True
            )
        except Exception as exc:
            logging.error("ServiceError: %s", exc)
            return abort(500, "Service Error")

        delcookie = delete_cookie()
        return self.response(binding, http_args, delcookie)


# ----------------------------------------------------------------------------
# Cookie handling
# ----------------------------------------------------------------------------


def delete_cookie():
    cookie = {}
    cookie["value"] = ""
    cookie["path"] = "/"
    cookie["max_age"] = 0
    return cookie


def make_cookie(*args):
    cookie = {}

    data = ":".join(args)
    if not isinstance(data, six.binary_type):
        data = data.encode("ascii")

    data64 = base64.b64encode(data)
    if not isinstance(data64, six.string_types):
        data64 = data64.decode("ascii")

    cookie["value"] = data64
    cookie["path"] = "/"
    cookie["max_age"] = 5*60  # 5 minutes from now
    return cookie


def get_user(request):
    args = request.args
    cookie = request.cookies.get("idpauthn")

    if cookie:
        try:
            data = base64.b64decode(cookie)
            if not isinstance(data, six.string_types):
                data = data.decode("utf-8")
            key, authn_ref = data.split(":", 1)
            user = IDP.cache.uid2user[key]
            logging.info("=== USER FROM COOKIE ===")
        except (KeyError, TypeError):
            user = None
    else:
        try:
            key = args["id"]
            user = IDP.cache.uid2user[key]
            logging.info("=== USER FROM ARGS ===")
        except KeyError:
            user = None

    return user


# ----------------------------------------------------------------------------


app = Flask(__name__)


@app.route("/metadata")
def metadata():
    try:
        path = os.path.dirname(os.path.abspath(__file__))
        metadata = create_metadata_string(path, IDP.config)
        return Response(metadata, mimetype="text/xml")
    except Exception as ex:
        logging.error("An error occured while creating metadata: %s", ex)
        abort(500)


@app.route("/sso/redirect")
def sso():
    user = get_user(request)
    sso = SSO(request, user)
    return sso.redirect()


@app.route("/slo/redirect")
def slo():
    user = get_user(request)
    slo = SLO(request, user)
    return slo.redirect()


@app.route("/verify", methods=["POST"])
def verify():
    return do_verify(request.form)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", dest="config_file", default="./idp_conf.py")
    args = parser.parse_args()

    spec = importlib.util.spec_from_file_location("idp_conf", args.config_file)
    config = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(config)

    CONFIG = config

    AUTHN_BROKER = AuthnBroker()
    AUTHN_BROKER.add(authn_context_class_ref(PASSWORD), username_password_authn, 10, CONFIG.BASE)
    AUTHN_BROKER.add(authn_context_class_ref(UNSPECIFIED), "", 0, CONFIG.BASE)

    server_config = config_factory("idp", CONFIG.CONFIG)
    IDP = server.Server(config=server_config, cache=Cache())
    IDP.ticket = {}

    HOST = CONFIG.HOST
    PORT = CONFIG.PORT

    logging.info("Server starting")
    logging.info("IDP listening on %s:%s", HOST, PORT)
    app.run(host=HOST, port=PORT)
