http_signature
==============

[![Build Status](https://travis-ci.org/potatosalad/erlang-http_signature.png?branch=master)](https://travis-ci.org/potatosalad/erlang-http_signature)

Erlang implementation of Joyent's HTTP Signature Scheme

Build
-----

	$ make

Usage
-----

First, let's generate a RSA key using `ssh-keygen`.

```bash
$ ssh-keygen -t rsa -b 2048 -C "test@rsa" -P "password" -f test_rsa
Generating public/private rsa key pair.
Your identification has been saved in test_rsa.
Your public key has been saved in test_rsa.pub.
The key fingerprint is:
SHA256:5r3JqF/pljbXB7+uKboUXWjbShwUgABSHJcX73l/igg test@rsa
The key's randomart image is:
+---[RSA 2048]----+
| .o+ooo.o..o.    |
|  .... o. . .    |
|      .  . + .   |
|        . = =    |
|        S+ * .   |
|       o .+.o .  |
|       E..+o o + |
|        o=*+o = o|
|      .oo*B+.+o+.|
+----[SHA256]-----+
```

Now let's use our key to sign and verify a request.

```erlang
Signer = http_signature_signer:from_file("password", "test_rsa"),
Result = http_signature:sign_request(get, <<"/path">>, #{}, [{key_id, <<"my-key-id">>}], Signer),

%% You can also store the key_id directly on the signer:
KeyedSigner = http_signature_signer:key_id(<<"my-key-id">>, Signer),
Result = http_signature:sign_request(get, <<"/path">>, #{}, [], KeyedSigner),

%% The following two lines are effectively the same:
Verifier = http_signature_signer:to_verifier(Signer),
VerifierFromFile = http_signature_verifier:from_file("test_rsa.pub"),

%% {Method, Path, Headers} are returned from http_signature:sign_request/5
{Method, Path, Headers} = Result,

%% We can use these values to verify the signature stored in Headers
true = http_signature:verify_request(Method, Path, Headers, [], Verifier).
```
