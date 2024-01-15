#!/usr/bin/python3
# coding=utf-8

#   Copyright 2023 getcarrier.io
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

""" Route """

import uuid
import time
import base64
import urllib
import secrets
import datetime

import flask  # pylint: disable=E0401
import jwt  # pylint: disable=E0401
import jsonpath_rw  # pylint: disable=E0401

from pylon.core.tools import log  # pylint: disable=E0611,E0401,W0611
from pylon.core.tools import web  # pylint: disable=E0611,E0401

from tools import context  # pylint: disable=E0401
from tools import auth  # pylint: disable=E0401


def log_request_args():
    """ Send request args/form/headers to debug log """
    if not context.debug:
        return
    #
    log.info("===============")
    #
    args = flask.request.args
    log.info("Args:")
    for key, value in args.items():
        log.info("--> %s: %s", key, value)
    #
    log.info("---")
    #
    form = flask.request.form
    log.info("Form:")
    for key, value in form.items():
        log.info("--> %s: %s", key, value)
    #
    log.info("---")
    #
    headers = flask.request.headers
    log.info("Headers:")
    for key, value in headers.items():
        log.info("--> %s: %s", key, value)
    #
    log.info("===============")


def make_error_response(error, redirect_args, redirect_uri):
    """ Redirect with error response """
    redirect_args["error"] = error
    redirect_params = urllib.parse.urlencode(redirect_args)
    redirect_url = f'{redirect_uri}?{redirect_params}'
    return flask.redirect(redirect_url)


def clean_stale_data(client_state):
    """ Remove meta / expired access_tokens """
    now = int(time.time())
    #
    stale_tokens = set()
    #
    for token, expires_at in client_state["access_tokens"].items():
        if now > expires_at:
            stale_tokens.add(token)
    #
    while stale_tokens:
        token = stale_tokens.pop()
        client_state["access_tokens"].pop(token)
        client_state["access_token_to_meta"].pop(token)


def make_claim_item(item_type, item_data, auth_ctx):
    """ Make claim data item """
    auth_ctx_nameid = auth_ctx["provider_attr"]["nameid"]
    #
    if item_type == "raw":
        return item_data.get("data", ...)
    #
    if item_type == "nameid_map":
        return item_data.get("map", {}).get(auth_ctx_nameid, ...)
    #
    if item_type == "jsonpath_format":
        variables = {}
        #
        for key, schema in item_data.get("vars", {}).items():
            try:
                variables[key] = jsonpath_rw.parse(schema).find(auth_ctx)[0].value
            except:  # pylint: disable=W0702
                log.exception("Failed to set var data: %s -> %s", key, schema)
        #
        return item_data.get("template", "").format(**variables)
    #
    return ...


def make_claims(claims_schema, auth_ctx):
    """ Make claims data from auth context according to schema """
    result = {}
    #
    for claim, schema in claims_schema.items():
        if isinstance(schema, str):
            try:
                result[claim] = jsonpath_rw.parse(schema).find(auth_ctx)[0].value
            except:  # pylint: disable=W0702
                log.exception("Failed to set claim data: %s -> %s", claim, schema)
        elif isinstance(schema, dict) and "type" in schema:
            item_data = schema.copy()
            item_type = item_data.pop("type")
            item_claim = make_claim_item(item_type, item_data, auth_ctx)
            #
            if item_claim is not ...:
                result[claim] = item_claim
        else:
            result[claim] = schema
    #
    return result


class Route:  # pylint: disable=E1101,R0903
    """
        Route Resource

        self is pointing to current Module instance

        By default routes are prefixed with module name
        Example:
        - pylon is at "https://example.com/"
        - module name is "demo"
        - route is "/"
        Route URL: https://example.com/demo/

        web.route decorator takes the same arguments as Flask route
        Note: web.route decorator must be the last decorator (at top)
    """


    @web.route("/endpoints/authorization", methods=["GET", "POST"])
    def authorization(self):  # pylint: disable=R0911
        """ Route """
        log_request_args()
        if flask.request.method == "POST":
            args = flask.request.form
        else:
            args = flask.request.args
        #
        if "redirect_uri" not in args or not args["redirect_uri"].startswith("http"):
            return self.access_denied_reply()
        #
        redirect_uri = args.get("redirect_uri")
        redirect_args = {}
        #
        if "state" in args:
            redirect_args["state"] = args.get("state")
        #
        if "client_id" not in args or args["client_id"] not in self.client_state:
            return make_error_response(
                "unauthorized_client", redirect_args, redirect_uri
            )
        #
        for arg in ["scope", "response_type"]:
            if arg not in args:
                return make_error_response(
                    "invalid_request", redirect_args, redirect_uri
                )
        #
        if args.get("response_type") != "code":
            return make_error_response(
                "unsupported_response_type", redirect_args, redirect_uri
            )
        #
        scope = [item.strip() for item in args.get("scope").split(" ")]
        if "openid" not in scope:
            return make_error_response(
                "invalid_scope", redirect_args, redirect_uri
            )
        #
        client_id = args.get("client_id")
        client_state = self.client_state[client_id]
        clean_stale_data(client_state)
        # Auth check
        auth_ctx = auth.get_auth_context()
        if auth_ctx["done"] and \
                (
                        auth_ctx["expiration"] is None or
                        datetime.datetime.now() < auth_ctx["expiration"]
                ):
            # Make and save code
            code = secrets.token_urlsafe(
                client_state.get("code_bytes", self.descriptor.config.get("code_bytes", 32))
            )
            client_state["codes"].add(code)
            # Make redirect URL
            redirect_args["code"] = code
            redirect_params = urllib.parse.urlencode(redirect_args)
            redirect_url = f'{redirect_uri}?{redirect_params}'
            # Map code to meta
            auth_reference = auth.get_auth_reference()
            client_state["code_to_meta"][code] = {
                "auth_reference": auth_reference,
                "args": args.to_dict().copy(),
                "scope": scope,
            }
            # Auth done
            return flask.redirect(redirect_url)
        # Auth needed or expired
        openid_configuration = self.get_openid_configuration()
        authorization_uri = openid_configuration.get("authorization_endpoint")
        authorization_params = urllib.parse.urlencode(args.to_dict().copy())
        authorization_url = f'{authorization_uri}?{authorization_params}'
        #
        auth.set_auth_context({})
        target_token = auth.sign_target_url(authorization_url)
        return auth.access_needed_redirect(target_token)

    @web.route("/endpoints/token", methods=["POST"])
    def token(self):  # pylint: disable=R0914,R0912,R0915
        """ Route """
        log_request_args()
        form = flask.request.form
        headers = flask.request.headers
        #
        client_authenticated = False
        #
        if not client_authenticated and "Authorization" in headers:
            auth_data = headers.get("Authorization").split(" ", 1)
            auth_type = auth_data[0]
            #
            if auth_type.lower() == "basic":
                auth_info = base64.b64decode(auth_data[1]).decode().split(":", 1)
                #
                client_id = auth_info[0]
                client_secret = auth_info[1]
                #
                if client_id in self.client_state:
                    client_state = self.client_state[client_id]
                    #
                    if client_secret == client_state.get("client_secret", ""):
                        client_authenticated = True
        #
        if not client_authenticated and "client_id" in form:
            client_id = form.get("client_id")
            client_secret = form.get("client_secret", "")
            #
            if client_id in self.client_state:
                client_state = self.client_state[client_id]
                #
                if client_secret == client_state.get("client_secret", ""):
                    client_authenticated = True
        #
        if not client_authenticated:
            return {"error": "invalid_client"}, 400
        #
        clean_stale_data(client_state)
        #
        if form.get("grant_type", "") not in [
                "authorization_code", "refresh_token"
        ]:
            return {"error": "unsupported_grant_type"}, 400
        #
        if form.get("grant_type") == "authorization_code":
            code = form.get("code", "")
            #
            if code not in client_state["codes"]:
                return {"error": "invalid_grant"}, 400
            #
            client_meta = client_state["code_to_meta"].pop(code)
            client_state["codes"].discard(code)
        #
        if form.get("grant_type") == "refresh_token":
            refresh_token = form.get("refresh_token", "")
            #
            if refresh_token not in client_state["refresh_tokens"]:
                return {"error": "invalid_grant"}, 400
            #
            client_meta = client_state["refresh_token_to_meta"].pop(refresh_token)
            client_state["refresh_tokens"].discard(refresh_token)
        #
        # All checks passed, issue token(s)
        #
        expires_in = client_state.get(
            "token_expires_in", self.descriptor.config.get("token_expires_in", 3600)
        )
        access_token = secrets.token_urlsafe(
            client_state.get(
                "access_token_bytes", self.descriptor.config.get("access_token_bytes", 32)
            )
        )
        refresh_token = secrets.token_urlsafe(
            client_state.get(
                "refresh_token_bytes", self.descriptor.config.get("refresh_token_bytes", 32)
            )
        )
        issued_at = int(time.time())
        expires_at = issued_at + expires_in
        #
        openid_configuration = self.get_openid_configuration()
        auth_ctx = self.context.rpc_manager.call.auth_get_referenced_auth_context(
            client_meta["auth_reference"]
        )
        #
        auth_ctx_nameid = auth_ctx["provider_attr"]["nameid"]
        #
        id_token = {
            "iss": openid_configuration.get("issuer"),
            "aud": client_id,
            "iat": issued_at,
            "exp": expires_at,
            #
            "sub": str(uuid.uuid5(uuid.NAMESPACE_URL, auth_ctx_nameid)),
        }
        #
        if "nonce" in client_meta["args"]:
            id_token["nonce"] = client_meta["args"].get("nonce")
        #
        id_token_claims = make_claims(
            client_state.get("id_token_claims", {}),
            auth_ctx
        )
        id_token.update(id_token_claims)
        #
        client_state["access_tokens"][access_token] = expires_at
        client_state["access_token_to_meta"][access_token] = client_meta
        client_state["refresh_tokens"].add(refresh_token)
        client_state["refresh_token_to_meta"][refresh_token] = client_meta
        #
        return {
            "token_type": "Bearer",
            "expires_in": expires_in,
            "access_token": access_token,
            "refresh_token": refresh_token,
            "id_token": jwt.encode(id_token, self.rsa_key, algorithm="RS256"),
        }

    @web.route("/endpoints/jwks", methods=["GET"])
    def jwks(self):
        """ Route """
        public_jwk = jwt.get_algorithm_by_name("RS256").to_jwk(
            self.rsa_key.public_key(), as_dict=True,
        )
        #
        return {
            "keys": [
                public_jwk,
            ],
        }

    @web.route("/endpoints/userinfo", methods=["GET", "POST"])
    def userinfo(self):
        """ Route """
        log_request_args()
        headers = flask.request.headers
        #
        if "Authorization" not in headers:
            return {}, 401
        #
        auth_data = headers.get("Authorization").split(" ", 1)
        auth_type = auth_data[0]
        #
        if auth_type.lower() != "bearer":
            return {}, 401
        #
        access_token = auth_data[1]
        if access_token not in self.access_token_to_meta:
            return {}, 401
        #
        client_meta = self.access_token_to_meta[access_token]
        client_id = client_meta["args"].get("client_id")
        #
        client_state = self.client_state[client_id]
        clean_stale_data(client_state)
        #
        if access_token not in client_state["access_tokens"]:
            return {}, 401
        #
        auth_ctx = self.context.rpc_manager.call.auth_get_referenced_auth_context(
            client_meta["auth_reference"]
        )
        #
        auth_ctx_nameid = auth_ctx["provider_attr"]["nameid"]
        #
        userinfo = {
            "sub": str(uuid.uuid5(uuid.NAMESPACE_URL, auth_ctx_nameid)),
        }
        #
        userinfo_claims = make_claims(
            client_state.get("userinfo_claims", {}),
            auth_ctx
        )
        userinfo.update(userinfo_claims)
        #
        return userinfo

    @web.route("/endpoints/end_session", methods=["GET", "POST"])
    def end_session(self):
        """ Route """
        log_request_args()
        if flask.request.method == "POST":
            args = flask.request.form
        else:
            args = flask.request.args
        #
        # Currently no additional token/session invalidation is made here
        # May implement in the future (along with OpenID.Session/FrontChannel/BackChannel)
        #
        if "post_logout_redirect_uri" in args and "id_token_hint" in args:
            id_token = args.get("id_token_hint")
            redirect_uri = args.get("post_logout_redirect_uri")
            #
            try:
                jwt.decode(id_token, self.rsa_key.public_key(), algorithms=["RS256"])
                return flask.redirect(redirect_uri)
            except:  # pylint: disable=W0702
                pass
        #
        return flask.redirect(auth.descriptor.config.get("default_logout_url", "/"))
