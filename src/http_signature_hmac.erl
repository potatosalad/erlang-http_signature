%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <andrew@pixid.com>
%%% @copyright 2014-2017, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  07 Oct 2017 by Andrew Bennett <andrew@pixid.com>
%%%-------------------------------------------------------------------
-module(http_signature_hmac).
-behaviour(http_signature_algorithm).

-include("http_signature_utils.hrl").

%% http_signature_algorithm callbacks
-export([default_sign_algorithm/1]).
-export([generate_key/1]).
-export([sign/3]).
-export([ssh_hostkey_fingerprint/2]).
-export([verify/4]).

%% Macros
-define(INLINE_INT2HEX(Int),
	case Int of
		0 -> $0;
		1 -> $1;
		2 -> $2;
		3 -> $3;
		4 -> $4;
		5 -> $5;
		6 -> $6;
		7 -> $7;
		8 -> $8;
		9 -> $9;
		10 -> $a;
		11 -> $b;
		12 -> $c;
		13 -> $d;
		14 -> $e;
		15 -> $f
	end).

-define(INLINE_BIN2HEX_BC(Bin),
	<< <<
		?INLINE_INT2HEX(I div 16),
		?INLINE_INT2HEX(I rem 16)
	>> || << I >> <= Bin >>).

-define(INLINE_FINGERPRINT_BC(Bin),
	<< <<
		$:,
		?INLINE_INT2HEX(I div 16),
		?INLINE_INT2HEX(I rem 16)
	>> || << I >> <= Bin >>).

%%%===================================================================
%%% http_signature_algorithm callbacks
%%%===================================================================

default_sign_algorithm({hmac, _}) ->
	<<"hmac-sha256">>.

generate_key(ByteSize) when is_integer(ByteSize) andalso ByteSize >= 0 ->
	{hmac, crypto:strong_rand_bytes(ByteSize)};
generate_key(Key) when is_binary(Key) ->
	generate_key(byte_size(Key)).

sign({hmac, Secret}, Algorithm, Message) ->
	DigestType = algorithm_to_digest_type(Algorithm),
	crypto:hmac(DigestType, Secret, Message).

ssh_hostkey_fingerprint({hmac, Secret}, []) ->
	?INLINE_FINGERPRINT_BC(crypto:hash(md5, Secret)).

verify({hmac, Secret}, Algorithm, Signature, Message) ->
	Challenge = sign({hmac, Secret}, Algorithm, Message),
	http_signature:constant_time_compare(Challenge, Signature).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
algorithm_to_digest_type(Algorithm) ->
	case Algorithm of
		<<"hmac-sha1">> -> sha;
		<<"hmac-sha224">> -> sha224;
		<<"hmac-sha256">> -> sha256;
		<<"hmac-sha384">> -> sha384;
		<<"hmac-sha512">> -> sha512;
		_ -> ?http_signature_throw({bad_algorithm, Algorithm}, "Bad algorithm for HMAC key: ~s", [Algorithm])
	end.
