# U2f-lib sign arbitrary data

This is a modified fork of the u2flib-server to demostrate the ability to sign arbitrary data.

Https is a requirement for the browser u2f api.

The cert.pem file in the examples folder needs to be added to keychain access, in the system tab import the file.

Once it has been added to the system keychain get info for the certificate and set 'always trust' as the default in the trust section.

The python library requirements can be installed with `$ pip install -r dev-requirements.txt`

Run `python u2f_server.py` and go to [https://localhost:8081](https://localhost:8081)

--------

## u2flib-server
Provides functionality for working with the server side aspects of the U2F
protocol as defined in the [http://fidoalliance.org/specifications/download](FIDO specifications).
It supports Python 2.7, Python 3.3+ and PyPy 2.7+.

To read more about U2F and how to use a U2F library, visit
[http://developers.yubico.com/U2F](developers.yubico.com/U2F).

### Dependencies
u2flib-server depends on [https://pypi.python.org/pypi/cryptography](cryptography),
which requires libffi, OpenSSL, and a C compiler to build.
On a Debian or Ubuntu system, the build dependencies can be installed with
the following command:

  $ sudo apt-get install build-essential libssl-dev libffi-dev python-dev

For Windows the cryptography project provides prebuilt wheels.
For other platforms refer to [https://cryptography.io/en/stable/installation/](cryptography installation).

### Installation
u2flib-server is installable by running the following command:

  $ pip install python-u2flib-server

#### Check out the code
Run these commands to check out the source code:

  git clone https://github.com/Yubico/python-u2flib-server.git
  cd python-u2flib-server
  git submodule init
  git submodule update

#### Build a source release
To build a source release tar ball, run this command:

  python setup.py sdist

The resulting build will be created in the dist/ subdirectory.

### Example
See `examples/u2f_server.py` for a working example of a HTTP server for
U2F enrollment and authentication. `u2f_server.py` can be run as a stand-alone
server, and can be used to test a U2F client implementation, such as
python-u2flib-host, using for example cURL.

The examples below show cURL command to register a U2F device, and to
authenticate it.

#### Registration
Registration is initiated by sending a request to the server:
----
```shell
$ curl http://localhost:8081/enroll
```
```json
{"appId": "http://localhost:8081", "registeredKeys": [], "registerRequests": [{"version": "U2F_V2", "challenge": "9TCtiRRLBFqMokOWfepjej99lMKQhZfm20Sgtay-FMs"}]}
```
The RegisterRequest data is then fed to the U2F client, resulting in the
RegisterResponse data, which is passed back to the server:
```shell
$ curl http://localhost:8081/bind -d'data={"registrationData": "BQQNSrGo5bCdPyQNh1etGjidrJPBwTqittKe5DgKWyumIuGSnQxIHzM8Xd9W2eBrAJezRf7nIbxVRYkiA2G_teiEQLJa3tSyM-irgZHNXwsHC-YnfpXJ_uQkRMsgx37oAefHJI3RsBe4yCN2noa-jO1mgtgRrPK405QdcpI7xVk3XmAwggGHMIIBLqADAgECAgkAmb7osQyi7BwwCQYHKoZIzj0EATAhMR8wHQYDVQQDDBZZdWJpY28gVTJGIFNvZnQgRGV2aWNlMB4XDTEzMDcxNzE0MjEwM1oXDTE2MDcxNjE0MjEwM1owITEfMB0GA1UEAwwWWXViaWNvIFUyRiBTb2Z0IERldmljZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABDvhl91zfpg9n7DeCedcQ8gGXUnemiXoi-JEAxz-EIhkVsMPAyzhtJZ4V3CqMZ-MOUgICt2aMxacMX9cIa8dgS2jUDBOMB0GA1UdDgQWBBQNqL-TV04iaO6mS5tjGE6ShfexnjAfBgNVHSMEGDAWgBQNqL-TV04iaO6mS5tjGE6ShfexnjAMBgNVHRMEBTADAQH_MAkGByqGSM49BAEDSAAwRQIgXJWZdbvOWdhVaG7IJtn44o21Kmi8EHsDk4cAfnZ0r38CIQD6ZPi3Pl4lXxbY7BXFyrpkiOvCpdyNdLLYbSTbvIBQOTBEAiBs0qu8RRZDf4qJo5qnHOd6hNDu9aEyNGQCeHp47D6-9gIgST3rq1JrUn_xvPh5AAGsn64cLvJlF_V0MF2A73tkLOc", "clientData": "eyJvcmlnaW4iOiAiaHR0cDovL2xvY2FsaG9zdDo4MDgxIiwgImNoYWxsZW5nZSI6ICI5VEN0aVJSTEJGcU1va09XZmVwamVqOTlsTUtRaFpmbTIwU2d0YXktRk1zIiwgInR5cCI6ICJuYXZpZ2F0b3IuaWQuZmluaXNoRW5yb2xsbWVudCJ9","version":"U2F_V2"}'
```
```
true
```
The result, "true", indicates that registration was successful.

#### Authentication
Authentication for a previously registered U2F device is done by sending a
request to the server:
```shell
$ curl http://localhost:8081/sign
```
```json
{"appId": "http://localhost:8081", "registeredKeys": [{"version": "U2F_V2", "appId": "http://localhost:8081", "keyHandle": "slre1LIz6KuBkc1fCwcL5id-lcn-5CREyyDHfugB58ckjdGwF7jII3aehr6M7WaC2BGs8rjTlB1ykjvFWTdeYA"}], "challenge": "FnueX-NpT9kB7I41dc8DvPXU1-yj7oO_cBT3e9PWOAw"}
```
The AuthenticateRequest data is then fed to the U2F client, resulting in an
AuthenticateResponse object which is passed back to the server:
```shell
$ curl http://localhost:8081/verify -d'data={"keyHandle": "slre1LIz6KuBkc1fCwcL5id-lcn-5CREyyDHfugB58ckjdGwF7jII3aehr6M7WaC2BGs8rjTlB1ykjvFWTdeYA", "signatureData": "AQAAAAEwRgIhALhe7LTwnBHTPQQIGbn_wPR80S7-HPPliZh966vL3VeiAiEA35w-BVDROwdLGlztLgejw9bnXSrYY0-3EC-_qhi0XaI", "clientData": "eyJvcmlnaW4iOiAiaHR0cDovL2xvY2FsaG9zdDo4MDgxIiwgImNoYWxsZW5nZSI6ICJGbnVlWC1OcFQ5a0I3STQxZGM4RHZQWFUxLXlqN29PX2NCVDNlOVBXT0F3IiwgInR5cCI6ICJuYXZpZ2F0b3IuaWQuZ2V0QXNzZXJ0aW9uIn0"}'
```
```json
{"touch": 1, "counter": 1}
```


The response indicates success, giving the U2F devices internal counter value,
as well as the value of the user presence parameter.
