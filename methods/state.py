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
        log.info("Initializing state")
        self.client_state = {}
        self.access_token_to_meta = {}
        #
        for item in self.descriptor.config.get("clients", []):
            client_config = item.copy()
            client_id = client_config.pop("client_id")
            #
            self.client_state[client_id] = {
                "codes": set(),
                "access_tokens": {},
                "refresh_tokens": set(),
                #
                "code_to_meta": {},
                "refresh_token_to_meta": {},
                "access_token_to_meta": self.access_token_to_meta,
            }
            #
            self.client_state[client_id].update(client_config)
