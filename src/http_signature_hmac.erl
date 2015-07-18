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
-module(http_signature_hmac).
-behaviour(http_signature_signer).
-behaviour(http_signature_verifier).

-include("http_signature.hrl").

%% http_signature_signer callbacks
-export([algorithm/1]).
-export([decode/1]).
-export([decrypt/2]).
-export([encode/1]).
-export([encrypt/2]).
-export([sign/3]).
-export([to_verifier/1]).

%% http_signature_verifier callbacks
-export([public_decode/1]).
-export([public_encode/1]).
-export([verify/4]).

-record(http_signature_hmac, {
	key = undefined :: undefined | iodata()
}).

-type public() :: #http_signature_hmac{}.
-type secret() :: #http_signature_hmac{}.

-export_type([public/0]).
-export_type([secret/0]).

%%====================================================================
%% http_signature_signer callbacks
%%====================================================================

algorithm(#http_signature_hmac{}) ->
	{hmac, sha256}.

decode(SecretData) ->
	#http_signature_hmac{key=SecretData}.

decrypt(SecretPass, << IV:16/binary, EncryptedData/binary >>) ->
	SecretKey = crypto:hash(md5, SecretPass),
	PaddedData = crypto:block_decrypt(aes_cbc128, SecretKey, IV, EncryptedData),
	SecretData = unpad(PaddedData),
	#http_signature_hmac{key=SecretData}.

encode(#http_signature_hmac{key=SecretData}) ->
	SecretData.

encrypt(SecretPass, #http_signature_hmac{key=SecretData}) ->
	SecretKey = crypto:hash(md5, SecretPass),
	IV = crypto:rand_bytes(16),
	PaddedData = pad(SecretData),
	EncryptedData = crypto:block_encrypt(aes_cbc128, SecretKey, IV, PaddedData),
	<< IV/binary, EncryptedData/binary >>.

sign(Message, HashType, #http_signature_hmac{key=Key}) ->
	crypto:hmac(HashType, Key, Message).

to_verifier(#http_signature_hmac{key=PublicData}) ->
	http_signature_verifier:from_data({http_signature_hmac, PublicData}).

%%====================================================================
%% http_signature_verifier callbacks
%%====================================================================

public_decode(PublicData) ->
	#http_signature_hmac{key=PublicData}.

public_encode(#http_signature_hmac{key=PublicData}) ->
	PublicData.

verify(Message, HashType, Signature, HMAC=#http_signature_hmac{}) ->
	http_signature:constant_time_compare(Signature, sign(Message, HashType, HMAC)).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
pad(Bin) ->
	Extra = 16 - (byte_size(Bin) rem 16),
	pad(Extra, Bin).

%% @private
pad(0, Bin) ->
	<< Bin/binary, (crypto:rand_bytes(15))/binary, 0 >>;
pad(N, Bin) ->
	<< Bin/binary, (crypto:rand_bytes(N - 1))/binary, N >>.

%% @private
unpad(Bin) ->
	Size = byte_size(Bin),
	Len = case binary:last(Bin) of
		0 ->
			Size - 16;
		Pad ->
			Size - Pad
	end,
	binary:part(Bin, 0, Len).
