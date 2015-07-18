%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <andrew@pixid.com>
%%% @copyright 2014-2015, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  16 Jul 2015 by Andrew Bennett <andrew@pixid.com>
%%%-------------------------------------------------------------------
-module(http_signature_public_key).
-behaviour(http_signature_verifier).

-include("http_signature.hrl").

-include_lib("public_key/include/public_key.hrl").

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
	binary_part(<< <<
		$:,
		?INLINE_INT2HEX(I div 16),
		?INLINE_INT2HEX(I rem 16)
	>> || << I >> <= Bin >>, 1, (byte_size(Bin) * 3) - 1)).

%% http_signature_verifier callbacks
-export([public_decode/1]).
-export([public_encode/1]).
-export([verify/4]).

%% API
-export([fingerprint/1]).
-export([fingerprint/2]).

%% Types
-type public() :: public_key:public_key().

-export_type([public/0]).

%%====================================================================
%% http_signature_verifier callbacks
%%====================================================================

public_decode(PublicData) ->
	case public_key:ssh_decode(PublicData, auth_keys) of
		[ECDHKey={{A, B}, _} | _] when is_binary(A) andalso is_binary(B) ->
			http_signature_public_key_ecdh:public_decode(ECDHKey);
		[PublicKey | _] ->
			PublicKey;
		LoadError ->
			erlang:error({badarg, LoadError})
	end.

public_encode(PublicKey={{_, #'Dss-Parms'{}}, _}) ->
	public_key:ssh_encode([PublicKey], auth_keys);
public_encode(PublicKey={#'RSAPublicKey'{}, _}) ->
	public_key:ssh_encode([PublicKey], auth_keys);
public_encode(ECPublicKey={{#'ECPoint'{}, _}, _}) ->
	{{KeyType, PublicKey}, Attributes} = http_signature_public_key_ecdh:public_encode(ECPublicKey),
	Comment = proplists:get_value(comment, Attributes, ""),
	<<
		KeyType/binary, $\s,
		(base64:encode(PublicKey))/binary,
		(line_end(Comment))/binary
	>>.

verify(Message, Type, Signature, {PublicKey, _}) ->
	public_key:verify(Message, Type, Signature, PublicKey).

%%====================================================================
%% API functions
%%====================================================================

fingerprint(PublicKey) ->
	fingerprint(md5, PublicKey).

fingerprint(HashType, PublicKey) ->
	EncodedKey = extract_base64_key(public_encode(PublicKey)),
	DecodedKey = base64:decode(EncodedKey),
	?INLINE_FINGERPRINT_BC(crypto:hash(HashType, DecodedKey)).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
extract_base64_key(<< $\s, Rest/binary >>) ->
	extract_base64_key(Rest, <<>>);
extract_base64_key(<< _, Rest/binary >>) ->
	extract_base64_key(Rest).

%% @private
extract_base64_key(<< $\n, _/binary >>, Key) ->
	Key;
extract_base64_key(<< $\s, _/binary >>, Key) ->
	Key;
extract_base64_key(<< C, Rest/binary >>, Key) ->
	extract_base64_key(Rest, << Key/binary, C >>).

%% @private
line_end("") ->
	<< $\n >>;
line_end(Comment) ->
	<< $\s, (iolist_to_binary(Comment))/binary, $\n >>.
