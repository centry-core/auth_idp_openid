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

""" Method """

import flask  # pylint: disable=E0401

from pylon.core.tools import log  # pylint: disable=E0611,E0401
from pylon.core.tools import web  # pylint: disable=E0611,E0401


class Method:  # pylint: disable=E1101,R0903,W0201
    """
        Method Resource

        self is pointing to current Module instance

        web.method decorator takes zero or one argument: method name
        Note: web.method decorator must be the last decorator (at top)

    """

    @web.init()
    def _init(self):
        # Static routes for openid-configuration
        self.openid_configuration = None
        #
        if self.descriptor.config.get("use_static_openid_configuration", False):
            log.info("Setting static endpoint URLs")
            with self.context.app.app_context():
                self.openid_configuration = self.get_openid_configuration()

    @web.method()
    def get_openid_configuration(self):
        """ Method """
        if self.descriptor.config.get("use_static_openid_configuration", False) \
                and self.openid_configuration is not None:
            return self.openid_configuration
        #
        self_name = self.descriptor.name
        return {
            "issuer": flask.url_for(f"{self_name}.index", _external=True).rstrip("/"),
            "authorization_endpoint": flask.url_for(f"{self_name}.authorization", _external=True),
            "token_endpoint": flask.url_for(f"{self_name}.token", _external=True),
            "jwks_uri": flask.url_for(f"{self_name}.jwks", _external=True),
            "userinfo_endpoint": flask.url_for(f"{self_name}.userinfo", _external=True),
            "end_session_endpoint": flask.url_for(f"{self_name}.end_session", _external=True),
        }
