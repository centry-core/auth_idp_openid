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
import urllib
import secrets
import datetime

import flask  # pylint: disable=E0401
import jwt  # pylint: disable=E0401

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


    @web.route("/endpoints/authorization", methods=["GET"])
    def authorization(self):
        """ Route """
        log_request_args()
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
            redirect_args["error"] = "unauthorized_client"
            #
            redirect_params = urllib.parse.urlencode(redirect_args)
            redirect_url = f'{redirect_uri}?{redirect_params}'
            return flask.redirect(redirect_url)
        #
        client_id = args.get("client_id")
        client_state = self.client_state[client_id]
        # Make and save code
        code = secrets.token_urlsafe(
            self.descriptor.config.get("code_bytes", 32)
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
        }
        # Auth check
        auth_ctx = auth.get_auth_context()
        if auth_ctx["done"] and \
                (
                        auth_ctx["expiration"] is None or
                        datetime.datetime.now() < auth_ctx["expiration"]
                ):
            # Auth done
            return flask.redirect(redirect_url)
        # Auth needed or expired
        auth.set_auth_context({})
        target_token = auth.sign_target_url(redirect_url)
        return auth.access_needed_redirect(target_token)

    @web.route("/endpoints/token", methods=["POST"])
    def token(self):
        """ Route """
        log_request_args()
        #
        expires_in = 3600
        #
        issued_at = int(time.time())
        expires_at = issued_at + expires_in
        #
        access_token = str(uuid.uuid4())
        refresh_token = str(uuid.uuid4())
        #
        openid_configuration = self.get_openid_configuration()
        #
        id_token = jwt.encode(
            {
                "iss": openid_configuration.get("issuer"),
                "sub": str(uuid.uuid4()),
                "aud": "centry-auth-client-id",
                "exp": expires_at,
                "iat": issued_at,
                "roles": [],
                "preferred_username": "user",
            },
            self.rsa_key,
            algorithm="RS256",
        )
        #
        return {
            "token_type": "Bearer",
            "expires_in": expires_in,
            "access_token": access_token,
            "refresh_token": refresh_token,
            "id_token": id_token,
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

    @web.route("/endpoints/userinfo", methods=["GET"])
    def userinfo(self):
        """ Route """
        log_request_args()
        #
        return {
            "sub": "user",
            "name": "This User",
            "given_name": "This",
            "family_name": "User",
            "preferred_username": "user",
            "roles": [],
            "email": "user@example.com",
        }

    @web.route("/endpoints/end_session", methods=["GET"])
    def end_session(self):
        """ Route """
        log_request_args()
        #
        args = flask.request.args
        #
        if "post_logout_redirect_uri" in args:
            return flask.redirect(args.get("post_logout_redirect_uri"))
        #
        return {"auth": "Logout request received"}
