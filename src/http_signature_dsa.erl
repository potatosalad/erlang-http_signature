%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <andrew@pixid.com>
%%% @copyright 2014-2017, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  06 Oct 2017 by Andrew Bennett <andrew@pixid.com>
%%%-------------------------------------------------------------------
-module(http_signature_dsa).
-behaviour(http_signature_algorithm).

-include("http_signature_utils.hrl").
-include_lib("public_key/include/public_key.hrl").

%% API
-export([generate_key/2]).
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

generate_key(openssl_dsaparam, Params) ->
	try
		Arguments =
			case Params of
				DSAParams=#'Dss-Parms'{} ->
					[
						public_key:der_encode('DSAParams', {params, DSAParams}),
						io_lib:format("dsaparam -inform DER -outform PEM -genkey -in /dev/stdin 2>/dev/null", [])
					];
				NumBits when is_integer(NumBits) andalso NumBits > 0 ->
					[
						io_lib:format("dsaparam -outform PEM -genkey ~w 2>/dev/null", [NumBits])
					]
			end,
		case erlang:apply(http_signature_openssl, call, Arguments) of
			{ok, 0, PEMBinary} ->
				[PEMEntryEncoded] = http_signature_public_key:pem_decode(PEMBinary),
				DSAPrivateKey = #'DSAPrivateKey'{} = http_signature_public_key:pem_entry_decode(PEMEntryEncoded),
				{ok, DSAPrivateKey};
			{ok, ExitStatus, Output} ->
				erlang:error({exit_status, {ExitStatus, Output}});
			{error, OpensslError} ->
				erlang:error(OpensslError)
		end
	catch
		Class:Reason ->
			Stacktrace = erlang:get_stacktrace(),
			{error, {Class, Reason, Stacktrace}}
	end.

%%%===================================================================
%%% http_signature_algorithm callbacks
%%%===================================================================

default_sign_algorithm(#'DSAPrivateKey'{}) ->
	<<"dsa-sha1">>.

encode_pem(DSAPrivateKey = #'DSAPrivateKey'{}) ->
	PEMEntry = http_signature_public_key:pem_entry_encode('DSAPrivateKey', DSAPrivateKey),
	http_signature_public_key:pem_encode([PEMEntry]);
encode_pem(DSAPublicKey = {_, #'Dss-Parms'{}}) ->
	PEMEntry = http_signature_public_key:pem_entry_encode('SubjectPublicKeyInfo', DSAPublicKey),
	http_signature_public_key:pem_encode([PEMEntry]).

encode_pem(DSAPrivateKey = #'DSAPrivateKey'{}, Password) ->
	CipherInfo = {"AES-128-CBC", crypto:strong_rand_bytes(16)},
	PasswordString = erlang:binary_to_list(erlang:iolist_to_binary(Password)),
	PEMEntry = http_signature_public_key:pem_entry_encode('DSAPrivateKey', DSAPrivateKey, {CipherInfo, PasswordString}),
	http_signature_public_key:pem_encode([PEMEntry]).

generate_key({_, DSAParams=#'Dss-Parms'{}}) ->
	generate_key(DSAParams);
generate_key(Params)
		when (is_integer(Params) andalso Params > 0)
		orelse is_tuple(Params) ->
	try_generate_key([
		openssl_dsaparam
	], Params).

sign(DSAPrivateKey=#'DSAPrivateKey'{}, Algorithm, Message) ->
	DigestType = algorithm_to_digest_type(Algorithm),
	public_key:sign(Message, DigestType, DSAPrivateKey).

verify(DSAPublicKey={_, #'Dss-Parms'{}}, Algorithm, Signature, Message) ->
	DigestType = algorithm_to_digest_type(Algorithm),
	public_key:verify(Message, DigestType, Signature, DSAPublicKey).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
algorithm_to_digest_type(Algorithm) ->
	case Algorithm of
		<<"dsa-sha1">> -> sha;
		_ -> ?http_signature_throw({bad_algorithm, Algorithm}, "Bad algorithm for DSA key: ~s", [Algorithm])
	end.

%% @private
try_generate_key([Method | Methods], Params) ->
	case generate_key(Method, Params) of
		{ok, DSAPrivateKey = #'DSAPrivateKey'{}} ->
			DSAPrivateKey;
		{error, {Class, Reason, Stacktrace}} ->
			try_generate_key(Methods, Params, Class, Reason, Stacktrace)
	end.

%% @private
try_generate_key([Method | Methods], Params, Class, Reason, Stacktrace) ->
	case generate_key(Method, Params) of
		{ok, DSAPrivateKey = #'DSAPrivateKey'{}} ->
			DSAPrivateKey;
		{error, _} ->
			try_generate_key(Methods, Params, Class, Reason, Stacktrace)
	end;
try_generate_key([], _Params, Class, Reason, Stacktrace) ->
	erlang:raise(Class, Reason, Stacktrace).
