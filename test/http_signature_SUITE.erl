%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
-module(http_signature_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("public_key/include/public_key.hrl").

%% ct.
-export([all/0]).
-export([groups/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([init_per_group/2]).
-export([end_per_group/2]).

%% Tests.
-export([c_1_default_test/1]).
-export([c_2_basic_test/1]).
-export([c_3_all_headers_test/1]).

%% Macros.
-define(tv_ok(T, M, F, A, E),
	case erlang:apply(M, F, A) of
		E ->
			ok;
		T ->
			ct:fail({{M, F, A}, {expected, E}, {got, T}})
	end).

all() ->
	[
		{group, 'draft-cavage-http-signatures'}
	].

groups() ->
	[
		{'draft-cavage-http-signatures', [parallel], [
			c_1_default_test,
			c_2_basic_test,
			c_3_all_headers_test
		]}
	].

init_per_suite(Config) ->
	_ = application:ensure_all_started(http_signature),
	Config.

end_per_suite(_Config) ->
	_ = application:stop(http_signature),
	ok.

init_per_group('draft-cavage-http-signatures', Config) ->
	[
		{public_key_pem, <<
			"-----BEGIN PUBLIC KEY-----\n"
			"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDCFENGw33yGihy92pDjZQhl0C3\n"
			"6rPJj+CvfSC8+q28hxA161QFNUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6\n"
			"Z4UMR7EOcpfdUE9Hf3m/hs+FUR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJw\n"
			"oYi+1hqp1fIekaxsyQIDAQAB\n"
			"-----END PUBLIC KEY-----\n"
		>>},
		{secret_key_pem, <<
			"-----BEGIN RSA PRIVATE KEY-----\n"
			"MIICXgIBAAKBgQDCFENGw33yGihy92pDjZQhl0C36rPJj+CvfSC8+q28hxA161QF\n"
			"NUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6Z4UMR7EOcpfdUE9Hf3m/hs+F\n"
			"UR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJwoYi+1hqp1fIekaxsyQIDAQAB\n"
			"AoGBAJR8ZkCUvx5kzv+utdl7T5MnordT1TvoXXJGXK7ZZ+UuvMNUCdN2QPc4sBiA\n"
			"QWvLw1cSKt5DsKZ8UETpYPy8pPYnnDEz2dDYiaew9+xEpubyeW2oH4Zx71wqBtOK\n"
			"kqwrXa/pzdpiucRRjk6vE6YY7EBBs/g7uanVpGibOVAEsqH1AkEA7DkjVH28WDUg\n"
			"f1nqvfn2Kj6CT7nIcE3jGJsZZ7zlZmBmHFDONMLUrXR/Zm3pR5m0tCmBqa5RK95u\n"
			"412jt1dPIwJBANJT3v8pnkth48bQo/fKel6uEYyboRtA5/uHuHkZ6FQF7OUkGogc\n"
			"mSJluOdc5t6hI1VsLn0QZEjQZMEOWr+wKSMCQQCC4kXJEsHAve77oP6HtG/IiEn7\n"
			"kpyUXRNvFsDE0czpJJBvL/aRFUJxuRK91jhjC68sA7NsKMGg5OXb5I5Jj36xAkEA\n"
			"gIT7aFOYBFwGgQAQkWNKLvySgKbAZRTeLBacpHMuQdl1DfdntvAyqpAZ0lY0RKmW\n"
			"G6aFKaqQfOXKCyWoUiVknQJAXrlgySFci/2ueKlIE1QqIiLSZ8V8OlpFLRnb1pzI\n"
			"7U1yQXnTAEFYM560yJlzUpOb1V4cScGd365tiSMvxLOvTA==\n"
			"-----END RSA PRIVATE KEY-----\n"
		>>},
		{request, http_signature_request:new(post, <<"/foo?param=value&pet=dog">>, #{
			<<"Host">> => <<"example.com">>,
			<<"Date">> => <<"Thu, 05 Jan 2014 21:31:40 GMT">>,
			<<"Content-Type">> => <<"application/json">>,
			<<"Digest">> => <<"SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=">>,
			<<"Content-Length">> => <<"18">>
		})}
		| Config
	];
init_per_group(smoke, Config) ->
	[
		{sign_and_verify, [
			{dsa, [sha]},
			{ecdsa, [sha, sha256, sha512]},
			{hmac, [sha, sha256, sha512]},
			{rsa, [sha, sha256, sha512]}
		]},
		{sign_and_verify_request, [
			{get, <<"/path">>, #{}, [{key_id, <<"key_id">>}]},
			{get, <<"/path">>, #{ <<"extra">> => <<"val">> }, [{headers, [<<"date">>, <<"extra">>]}, {key_id, <<"key_id">>}]},
			{put, <<"/path">>, #{}, [{headers, [<<"(request-target)">>, <<"x-date">>]}, {key_id, <<"key_id">>}]}
		]}
		| Config
	].

end_per_group(_Group, _Config) ->
	ok.

%%====================================================================
%% Tests
%%====================================================================

c_1_default_test(Config) ->
	SecretKey = maps:update(id, <<"Test">>, http_signature_key:decode_pem(?config(secret_key_pem, Config))),
	PublicKey = maps:update(id, <<"Test">>, http_signature_key:decode_pem(?config(public_key_pem, Config))),
	Request = #{ method := Method, path := Path, headers := Headers } = ?config(request, Config),
	HeadersParameter = [],
	ExpectedSignatureString = <<
		"date: Thu, 05 Jan 2014 21:31:40 GMT"
	>>,
	ok = ?tv_ok(BadSignatureString, http_signature_string, new, [Method, Path, Headers, HeadersParameter], ExpectedSignatureString),
	ExpectedHeaders = maps:put(<<"authorization">>, <<
		"Signature algorithm=\"rsa-sha256\",keyId=\"Test\","
		"signature=\"jKyvPcxB4JbmYY4mByyBY7cZfNl4OW9HpFQlG7N4YcJPteKTu4MW"
		"CLyk+gIr0wDgqtLWf9NLpMAMimdfsH7FSWGfbMFSrsVTHNTk0rK3usrfFnti1dx"
		"sM4jl0kYJCKTGI/UWkqiaxwNiKqGcdlEDrTcUhhsFsOIo8VhddmZTZ8w=\""
	>>, Headers),
	ExpectedRequest = Request#{ headers := ExpectedHeaders },
	Signer = http_signature_signer:new(SecretKey, <<"rsa-sha256">>, HeadersParameter),
	ok = ?tv_ok(BadRequest, http_signature_request, sign, [Request, Signer], ExpectedRequest),
	Verifier = http_signature_verifier:new(PublicKey, [<<"rsa-sha256">>], HeadersParameter),
	ok = ?tv_ok(BadSecretVerify, http_signature_request, verify, [ExpectedRequest, Signer], true),
	ok = ?tv_ok(BadPublictVerify, http_signature_request, verify, [ExpectedRequest, Verifier], true),
	ok.

c_2_basic_test(Config) ->
	SecretKey = maps:update(id, <<"Test">>, http_signature_key:decode_pem(?config(secret_key_pem, Config))),
	PublicKey = maps:update(id, <<"Test">>, http_signature_key:decode_pem(?config(public_key_pem, Config))),
	Request = #{ method := Method, path := Path, headers := Headers } = ?config(request, Config),
	HeadersParameter = [<<"(request-target)">>, <<"host">>, <<"date">>],
	ExpectedSignatureString = <<
		"(request-target): post /foo?param=value&pet=dog\n"
		"host: example.com\n"
		"date: Thu, 05 Jan 2014 21:31:40 GMT"
	>>,
	ok = ?tv_ok(BadSignatureString, http_signature_string, new, [Method, Path, Headers, HeadersParameter], ExpectedSignatureString),
	ExpectedHeaders = maps:put(<<"authorization">>, <<
		"Signature algorithm=\"rsa-sha256\",headers=\"(request-target) host"
		" date\",keyId=\"Test\",signature=\"HUxc9BS3P/kPhS"
		"mJo+0pQ4IsCo007vkv6bUm4Qehrx+B1Eo4Mq5/6KylET72ZpMUS80XvjlOPjKzx"
		"feTQj4DiKbAzwJAb4HX3qX6obQTa00/qPDXlMepD2JtTw33yNnm/0xV7fQuvILN"
		"/ys+378Ysi082+4xBQFwvhNvSoVsGv4=\""
	>>, Headers),
	ExpectedRequest = Request#{ headers := ExpectedHeaders },
	Signer = http_signature_signer:new(SecretKey, <<"rsa-sha256">>, HeadersParameter),
	ok = ?tv_ok(BadRequest, http_signature_request, sign, [Request, Signer], ExpectedRequest),
	Verifier = http_signature_verifier:new(PublicKey, [<<"rsa-sha256">>], HeadersParameter),
	ok = ?tv_ok(BadSecretVerify, http_signature_request, verify, [ExpectedRequest, Signer], true),
	ok = ?tv_ok(BadPublictVerify, http_signature_request, verify, [ExpectedRequest, Verifier], true),
	ok.

c_3_all_headers_test(Config) ->
	SecretKey = maps:update(id, <<"Test">>, http_signature_key:decode_pem(?config(secret_key_pem, Config))),
	PublicKey = maps:update(id, <<"Test">>, http_signature_key:decode_pem(?config(public_key_pem, Config))),
	Request = #{ method := Method, path := Path, headers := Headers } = ?config(request, Config),
	HeadersParameter = [<<"(request-target)">>, <<"host">>, <<"date">>, <<"content-type">>, <<"digest">>, <<"content-length">>],
	ExpectedSignatureString = <<
		"(request-target): post /foo?param=value&pet=dog\n"
		"host: example.com\n"
		"date: Thu, 05 Jan 2014 21:31:40 GMT\n"
		"content-type: application/json\n"
		"digest: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=\n"
		"content-length: 18"
	>>,
	ok = ?tv_ok(BadSignatureString, http_signature_string, new, [Method, Path, Headers, HeadersParameter], ExpectedSignatureString),
	ExpectedHeaders = maps:put(<<"authorization">>, <<
		"Signature algorithm=\"rsa-sha256\",headers=\"(request-target) host"
		" date content-type digest content-length\",keyId=\"Test\","
		"signature=\"Ef7MlxLXoBovhil3AlyjtBwAL9g4TN3tibLj7uuNB3CROat/9Kae"
		"Q4hW2NiJ+pZ6HQEOx9vYZAyi+7cmIkmJszJCut5kQLAwuX+Ms/mUFvpKlSo9StS"
		"2bMXDBNjOh4Auj774GFj4gwjS+3NhFeoqyr/MuN6HsEnkvn6zdgfE2i0=\""
	>>, Headers),
	ExpectedRequest = Request#{ headers := ExpectedHeaders },
	Signer = http_signature_signer:new(SecretKey, <<"rsa-sha256">>, HeadersParameter),
	ok = ?tv_ok(BadRequest, http_signature_request, sign, [Request, Signer], ExpectedRequest),
	Verifier = http_signature_verifier:new(PublicKey, [<<"rsa-sha256">>], HeadersParameter),
	ok = ?tv_ok(BadSecretVerify, http_signature_request, verify, [ExpectedRequest, Signer], true),
	ok = ?tv_ok(BadPublictVerify, http_signature_request, verify, [ExpectedRequest, Verifier], true),
	ok.

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------
