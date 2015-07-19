http_signature
==============

[![Build Status](https://travis-ci.org/potatosalad/erlang-http_signature.png?branch=master)](https://travis-ci.org/potatosalad/erlang-http_signature)

Erlang and Elixir implementations of Joyent's HTTP Signature Scheme

Build
-----

```bash
$ make
```

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

### Erlang

```erlang
Signer = http_signature_signer:from_file("password", "test_rsa"),
Result = http_signature:sign_request(get, <<"/path">>, #{}, [{key_id, <<"my-key-id">>}], Signer),

%% You can also store the key_id directly on the signer:
KeyedSigner = http_signature_signer:key_id(<<"my-key-id">>, Signer),
KeyedResult = http_signature:sign_request(get, <<"/path">>, #{}, [], KeyedSigner),

%% The following two lines are effectively the same:
Verifier = http_signature_signer:to_verifier(Signer),
VerifierFromFile = http_signature_verifier:from_file("test_rsa.pub"),

%% {Method, Path, Headers} are returned from http_signature:sign_request/5
{Method, Path, Headers} = Result,

%% Here's what the Headers now look like:
#{<<"authorization">> := <<"Signature keyId=\"my-key-id\",algorithm=\"rsa-sha256\",signature=\"Y1iuKoOasY4imseyj5dpHvTNJ4j6Aic5UuJn4i2r0iFnKDFKk1ya7PaUNP85tdv5zoeLTZn+A32U7v9NFnFl3/iw+R0SLhHzwm7/tssTteYsKyYVv+8WKsz6tjUXLMowAi6fI0JhztVt3YTtOvMhdSVJCRkWUkJqPsJbfS2bcsI5lrtn/AP5rPG1C7fyf63VRkuXWJ+NyruJNLOUIgCiNNEH2+ZnSrXgZf986EBzY9Xagjj+GStn3UvlnohsiPesioLQxCWDWXDEL9vD9bOfhDjLzZQN+G/fTsQCwhhhS5smVr4KiKzMKPsd6xbTnBRUX3gCfYWRIt27nCqsHOf3ug==\"">>, <<"date">> := <<"Sat, 18 Jul 2015 00:16:25 GMT">>} = Headers,

%% We can use these values to verify the signature stored in Headers
true = http_signature:verify_request(Method, Path, Headers, [], Verifier).
```

### Elixir

```elixir
signer = HTTPSignature.Signer.from_file("password", "test_rsa")
result = HTTPSignature.sign_request(:get, "/path", %{}, [key_id: "my-key-id"], signer)

# You can also store the key_id directly on the signer:
signer = %{signer | key_id: "my-key-id"}
result = HTTPSignature.sign_request(:get, "/path", %{}, [], signer)

# The following two lines are effectively the same:
verifier = HTTPSignature.Signer.to_verifier(signer)
verifier = HTTPSignature.Verifier.from_file("test_rsa.pub")

# {method, path, headers} are returned from HTTPSignature.sign_request/5
{method, path, headers} = result

# Here's what the headers now look like:
%{"authorization" => "Signature keyId=\"my-key-id\",algorithm=\"rsa-sha256\",signature=\"eLiKGL6DaLQoha57xy8KAtCVzihw0h+hVVkyY0oNxaG4Nx/AfeM6/f/BNQP7aWKExWzkjs9w2bbTdtz9r+1A7YSkoCmEuSRCGE7N7AyyULWM1k7W1nZsceVL0uVyMt7ZF23aklf5CBuCYEa7DIot4wf6ekhaEqd+Z0rHr6VGFidyHxaYUTFHtzMLIbm37uXeI52FBNIJPQpceu0SY1Mf+pZyuk8c28P1UDZi3EJV4vgFcUUSClszTRSUYBw1cerEbqm0vN+q7thgvXE+jJXWkXCdUqi9lBDblruF9aUBtINaSwbr3UB4tXS4LMZFKxMfPF/LmYBdcjZE95l884DrRg==\"", "date" => "Sun, 19 Jul 2015 00:05:13 GMT"} = headers

# We can use these values to verify the signature stored in headers
true = HTTPSignature.verify_request(method, path, headers, [], verifier).
```
