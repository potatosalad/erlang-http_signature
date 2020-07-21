%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <andrew@pixid.com>
%%% @copyright 2014-2017, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  08 Aug 2017 by Andrew Bennett <andrew@pixid.com>
%%%-------------------------------------------------------------------
-module(http_signature_rsa).
-behaviour(http_signature_algorithm).

-include("http_signature_utils.hrl").
-include_lib("public_key/include/public_key.hrl").

%% API
-export([generate_key/3]).
%% http_signature_algorithm callbacks
-export([default_sign_algorithm/1]).
-export([encode_pem/1]).
-export([encode_pem/2]).
-export([generate_key/1]).
-export([sign/3]).
-export([verify/4]).

%%%===================================================================
%%% API functions
%%%===================================================================

generate_key(crypto, ModulusSize, ExponentSize)
		when is_integer(ModulusSize) andalso ModulusSize > 0
		andalso is_integer(ExponentSize) andalso ExponentSize > 0 ->
	try
		RSAPrivateKey = #'RSAPrivateKey'{} = public_key:generate_key({rsa, ModulusSize, ExponentSize}),
		{ok, RSAPrivateKey}
	catch
		Class:Reason:Stacktrace ->
			{error, {Class, Reason, Stacktrace}}
	end;
generate_key(cutkey, ModulusSize, ExponentSize)
		when is_integer(ModulusSize) andalso ModulusSize > 0
		andalso is_integer(ExponentSize) andalso ExponentSize > 0 ->
	_ = code:ensure_loaded(cutkey),
	_ = application:ensure_all_started(cutkey),
	try
		case cutkey:rsa(ModulusSize, ExponentSize, [{return, key}]) of
			{ok, RSAPrivateKey = #'RSAPrivateKey'{}} ->
				{ok, RSAPrivateKey};
			{error, CutkeyError} ->
				erlang:error(CutkeyError)
		end
	catch
		Class:Reason:Stacktrace ->
			{error, {Class, Reason, Stacktrace}}
	end;
generate_key(openssl_genpkey, ModulusSize, ExponentSize)
		when is_integer(ModulusSize) andalso ModulusSize > 0
		andalso is_integer(ExponentSize) andalso ExponentSize > 0 ->
	Args = io_lib:format(
		"genpkey "
		"-algorithm RSA "
		"-pkeyopt rsa_keygen_bits:~w "
		"-pkeyopt rsa_keygen_pubexp:~w "
		"2>/dev/null", [
		ModulusSize,
		ExponentSize
	]),
	try
		case http_signature_openssl:call(Args) of
			{ok, 0, PEMBinary} ->
				[PEMEntryEncoded] = http_signature_public_key:pem_decode(PEMBinary),
				RSAPrivateKey = #'RSAPrivateKey'{} = http_signature_public_key:pem_entry_decode(PEMEntryEncoded),
				{ok, RSAPrivateKey};
			{ok, ExitStatus, Output} ->
				erlang:error({exit_status, {ExitStatus, Output}});
			{error, OpensslError} ->
				erlang:error(OpensslError)
		end
	catch
		Class:Reason:Stacktrace ->
			{error, {Class, Reason, Stacktrace}}
	end;
generate_key(openssl_genrsa, ModulusSize, ExponentSize)
		when is_integer(ModulusSize) andalso ModulusSize > 0
		andalso is_integer(ExponentSize) andalso (ExponentSize =:= 3 orelse ExponentSize =:= 65537) ->
	Args = io_lib:format(
		"genrsa "
		"~s "
		"~w "
		"2>/dev/null", [
		case ExponentSize of
			3 -> "-3";
			65537 -> "-f4"
		end,
		ModulusSize
	]),
	try
		case http_signature_openssl:call(Args) of
			{ok, 0, PEMBinary} ->
				[PEMEntryEncoded] = http_signature_public_key:pem_decode(PEMBinary),
				RSAPrivateKey = #'RSAPrivateKey'{} = http_signature_public_key:pem_entry_decode(PEMEntryEncoded),
				{ok, RSAPrivateKey};
			{ok, ExitStatus, Output} ->
				erlang:error({exit_status, {ExitStatus, Output}});
			{error, OpensslError} ->
				erlang:error(OpensslError)
		end
	catch
		Class:Reason:Stacktrace ->
			{error, {Class, Reason, Stacktrace}}
	end.

%%%===================================================================
%%% http_signature_algorithm callbacks
%%%===================================================================

default_sign_algorithm(#'RSAPrivateKey'{}) ->
	<<"rsa-sha256">>.

encode_pem(RSAPrivateKey = #'RSAPrivateKey'{}) ->
	PEMEntry = http_signature_public_key:pem_entry_encode('RSAPrivateKey', RSAPrivateKey),
	http_signature_public_key:pem_encode([PEMEntry]);
encode_pem(RSAPublicKey = #'RSAPublicKey'{}) ->
	PEMEntry = http_signature_public_key:pem_entry_encode('SubjectPublicKeyInfo', RSAPublicKey),
	http_signature_public_key:pem_encode([PEMEntry]).

encode_pem(RSAPrivateKey = #'RSAPrivateKey'{}, Password) ->
	CipherInfo = {"AES-128-CBC", crypto:strong_rand_bytes(16)},
	PasswordString = erlang:binary_to_list(erlang:iolist_to_binary(Password)),
	PEMEntry = http_signature_public_key:pem_entry_encode('RSAPrivateKey', RSAPrivateKey, {CipherInfo, PasswordString}),
	http_signature_public_key:pem_encode([PEMEntry]).

generate_key(#'RSAPrivateKey'{ modulus = N, publicExponent = E }) ->
	generate_key({int_to_bit_size(N), E});
generate_key(#'RSAPublicKey'{ modulus = N, publicExponent = E }) ->
	generate_key({int_to_bit_size(N), E});
generate_key(ModulusSize) when is_integer(ModulusSize) ->
	generate_key({ModulusSize, 65537});
generate_key({ModulusSize, ExponentSize})
		when is_integer(ModulusSize) andalso ModulusSize > 0
		andalso is_integer(ExponentSize) andalso ExponentSize > 0 ->
	try_generate_key([
		crypto,
		cutkey,
		openssl_genpkey,
		openssl_genrsa
	], ModulusSize, ExponentSize).

sign(RSAPrivateKey=#'RSAPrivateKey'{}, Algorithm, Message) ->
	DigestType = algorithm_to_digest_type(Algorithm),
	public_key:sign(Message, DigestType, RSAPrivateKey).

verify(RSAPublicKey=#'RSAPublicKey'{}, Algorithm, Signature, Message) ->
	DigestType = algorithm_to_digest_type(Algorithm),
	public_key:verify(Message, DigestType, Signature, RSAPublicKey).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
algorithm_to_digest_type(Algorithm) ->
	case Algorithm of
		<<"rsa-sha1">> -> sha;
		<<"rsa-sha224">> -> sha224;
		<<"rsa-sha256">> -> sha256;
		<<"rsa-sha384">> -> sha384;
		<<"rsa-sha512">> -> sha512;
		_ -> ?http_signature_throw({bad_algorithm, Algorithm}, "Bad algorithm for RSA key: ~s", [Algorithm])
	end.

%% @private
int_to_bit_size(I) ->
	int_to_bit_size(I, 0).

%% @private
int_to_bit_size(0, B) ->
	B;
int_to_bit_size(I, B) ->
	int_to_bit_size(I bsr 1, B + 1).

%% @private
try_generate_key([Method | Methods], ModulusSize, ExponentSize) ->
	case generate_key(Method, ModulusSize, ExponentSize) of
		{ok, RSAPrivateKey = #'RSAPrivateKey'{version = 0}} ->
			RSAPrivateKey#'RSAPrivateKey'{version = 'two-prime'};
		{ok, RSAPrivateKey = #'RSAPrivateKey'{}} ->
			RSAPrivateKey;
		{error, {Class, Reason, Stacktrace}} ->
			try_generate_key(Methods, ModulusSize, ExponentSize, Class, Reason, Stacktrace)
	end.

%% @private
try_generate_key([Method | Methods], ModulusSize, ExponentSize, Class, Reason, Stacktrace) ->
	case generate_key(Method, ModulusSize, ExponentSize) of
		{ok, RSAPrivateKey = #'RSAPrivateKey'{version = 0}} ->
			RSAPrivateKey#'RSAPrivateKey'{version = 'two-prime'};
		{ok, RSAPrivateKey = #'RSAPrivateKey'{}} ->
			RSAPrivateKey;
		{error, _} ->
			try_generate_key(Methods, ModulusSize, ExponentSize, Class, Reason, Stacktrace)
	end;
try_generate_key([], _ModulusSize, _ExponentSize, Class, Reason, Stacktrace) ->
	erlang:raise(Class, Reason, Stacktrace).
