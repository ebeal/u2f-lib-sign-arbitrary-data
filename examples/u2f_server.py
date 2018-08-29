#!/usr/bin/env python
# Copyright (c) 2013 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

"""
Example web server providing single factor U2F enrollment and authentication.
It is intended to be run standalone in a single process, and stores user data
in memory only, with no permanent storage.

Enrollment will overwrite existing users.
If username is omitted, a default value of "user" will be used.

Any error will be returned as a stacktrace with a 400 response code.

Note that this is intended for test/demo purposes, not production use!

This example requires webob to be installed.
"""

import argparse
import json
import logging as log
import os
import traceback

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding
from flask import Flask, render_template, request
from u2flib_server.u2f import (begin_authentication, begin_registration,
                               complete_authentication, complete_registration)
from webob import exc
from webob.dec import wsgify

app = Flask(__name__)


def get_origin(environ):
    if environ.get('HTTP_HOST'):
        host = environ['HTTP_HOST']
    else:
        host = environ['SERVER_NAME']
        if environ['wsgi.url_scheme'] == 'https':
            if environ['SERVER_PORT'] != '443':
                host += ':' + environ['SERVER_PORT']
        else:
            if environ['SERVER_PORT'] != '80':
                host += ':' + environ['SERVER_PORT']

    return '%s://%s' % (environ['wsgi.url_scheme'], host)


users = {}
app_id = None

"""
Very basic server providing a REST API to enroll one or more U2F device with
a user, and to perform authentication with the enrolled devices.
Only one challenge is valid at a time.

Four calls are provided: enroll, bind, sign and verify. Each of these
expects a username parameter, and bind and verify expect a
second parameter, data, containing the JSON formatted data which is output
by the U2F browser API upon calling the ENROLL or SIGN commands.
"""

@app.route("/")
def entrypoint():
    return render_template("index.html")

@app.route("/enroll")
def enroll():
    app_id = get_origin(request.environ)
    username = request.args.get('username', 'user')
    data = request.data.decode()
    if username not in users:
        users[username] = {}
    user = users[username]
    enroll = begin_registration(app_id, user.get('_u2f_devices_', []))
    user['_u2f_enroll_'] = enroll.json
    return json.dumps(enroll.data_for_client)

@app.route("/bind", methods=['POST'])
def bind():
    app_id = get_origin(request.environ)
    username = request.args.get('username', 'user')
    data = request.data.decode()
    user = users[username]
    enroll = user.pop('_u2f_enroll_')
    device, cert = complete_registration(enroll, data, [app_id])
    user.setdefault('_u2f_devices_', []).append(device.json)
    print("U2F device enrolled. Username: %s", username)
    cert = x509.load_der_x509_certificate(cert, default_backend())
    log.debug("Attestation certificate:\n%s",
              cert.public_bytes(Encoding.PEM))

    return json.dumps(True)

@app.route("/sign", methods=['POST'])
def sign():
    app_id = get_origin(request.environ)
    username = request.args.get('username', 'user')
    data = request.data.decode()
    user = users[username]
    challenge = begin_authentication(
        app_id, user.get('_u2f_devices_', []), data)
    user['_u2f_challenge_'] = challenge.json
    return json.dumps(challenge.data_for_client)

@app.route("/verify", methods=['POST'])
def verify():
    app_id = get_origin(request.environ)
    username = request.args.get('username', 'user')
    data = request.data.decode()
    user = users[username]
    challenge = user.pop('_u2f_challenge_')
    device, c, t = complete_authentication(challenge, data, [app_id])
    return json.dumps({
        'keyHandle': device['keyHandle'],
        'touch': t,
        'counter': c
    })

if __name__ == '__main__':
    from wsgiref.simple_server import make_server

    parser = argparse.ArgumentParser(
        description='U2F test server',
        add_help=True,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('-i', '--interface', nargs='?', default='localhost',
                        help='network interface to bind to')
    parser.add_argument('-p', '--port', nargs='?', type=int, default=8081,
                        help='TCP port to bind to')

    args = parser.parse_args()

    log.basicConfig(level=log.DEBUG, format='%(asctime)s %(message)s',
                    datefmt='[%d/%b/%Y %H:%M:%S]')
    app.run(host=args.interface, port=args.port, ssl_context=('examples/cert.pem', 'examples/key.pem'), debug=True)
