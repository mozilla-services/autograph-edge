Autograph edge
==============

This is a small webapp that provides a public endpoint to autograph,
without exposing the entire service to the internet. It only supports XPI and
APK signing, and provides fine grained access control to only give clients the
ability to sign a given apk or xpi.

Client are expected to use curl - or similar - to interact with the webapp. An
unsigned file is submitted to the `/sign/` endpoint along with an authorization
token. The HTTP response contains the signed file.

```bash
curl -F "input=@/tmp/unsigned.apk" -o /tmp/signed.apk \
    -H "Authorization: <secret token>" \
    https://autograph-edge.example.com/sign
```

Configuration
-------------


The yaml file `autograph-edge.yaml` the location of the autograph server in
`url` and a list of authorizations.

```yaml
authorizations:
    - token: c4180d2963fffdcd1cd5a1a343225288b964d8934b809a7d76941ccf67cc8547
      addonid: myaddon@allizom.org
      user: alice
      key: fs5wgcer9qj819kfptdlp8gm227ewxnzvsuj9ztycsx08hfhzu
      signer: extensions-ecdsa
```

Each authorization has a `token` that clients send in their `Authorization` HTTP
headers.

The authorization also has a `user`, `key` and `signer` that are used to call
autograph (therefore these configuration items must come from the autograph
config).

If the authorization is for an add-on, it must also contain an `addonid`, which
is the ID of the add-on being signed. It can also include the optional params:

* `addonpkcs7digest`, a string of the PKCS7 digest algorithm to use
  (`"SHA1"` or `"SHA256"`). Defaults to `"SHA1"`.
* `addoncosealgorithms`, an array of strings for COSE Algorithms to
  sign the addon with. Defaults to an empty list [].

The sample configuration file in this repository can get you started.


Note that the token must be longer than 60 characters. You should use `openssl
rand -hex 32` to generate it.
