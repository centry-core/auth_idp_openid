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

import flask  # pylint: disable=E0401
import jwt  # pylint: disable=E0401

from pylon.core.tools import log  # pylint: disable=E0611,E0401,W0611
from pylon.core.tools import web  # pylint: disable=E0611,E0401


def log_request_args():
    """ Send request args/form/headers to debug log """
    log.debug("===============")
    #
    args = flask.request.args
    log.debug("Args:")
    for key, value in args.items():
        log.debug("--> %s: %s", key, value)
    #
    log.debug("---")
    #
    form = flask.request.form
    log.debug("Form:")
    for key, value in form.items():
        log.debug("--> %s: %s", key, value)
    #
    log.debug("---")
    #
    headers = flask.request.headers
    log.debug("Headers:")
    for key, value in headers.items():
        log.debug("--> %s: %s", key, value)
    #
    log.debug("===============")


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
        #
        args = flask.request.args
        #
        code = str(uuid.uuid4())
        state = args.get("state")
        redirect_uri = args.get("redirect_uri")
        #
        redirect_url = f'{redirect_uri}?code={code}&state={state}'
        #
        return flask.redirect(redirect_url)

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
        log_request_args()
        #
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
