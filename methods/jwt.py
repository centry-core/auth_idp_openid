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

from cryptography.hazmat.primitives.asymmetric import rsa  # pylint: disable=E0401
from cryptography.hazmat.primitives import serialization  # pylint: disable=E0401

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
        # Key for JWT
        local_app_key = self.context.settings.get("application", {}).get("SECRET_KEY", None)
        #
        if "jwt_private_key" in self.descriptor.config:
            log.info("Loading RSA key")
            #
            self.rsa_key = serialization.load_pem_private_key(
                self.descriptor.config.get("jwt_private_key").encode(),
                password=local_app_key.encode() if local_app_key is not None else None,
            )
        else:
            log.info("Generating RSA key")
            #
            self.rsa_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            #
            if local_app_key is not None:
                key_data = self.rsa_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.BestAvailableEncryption(
                        local_app_key.encode()
                    ),
                )
            else:
                key_data = self.rsa_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            #
            self.descriptor.config["jwt_private_key"] = key_data.decode()
        #
        if "jwt_public_key" not in self.descriptor.config:
            rsa_public_key = self.rsa_key.public_key()
            #
            public_key_data = rsa_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            #
            self.descriptor.config["jwt_public_key"] = public_key_data.decode()
