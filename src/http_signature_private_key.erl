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
-module(http_signature_private_key).
-behaviour(http_signature_signer).

-include("http_signature.hrl").

-include_lib("public_key/include/public_key.hrl").

%% http_signature_signer callbacks
-export([algorithm/1]).
-export([decode/1]).
-export([decrypt/2]).
-export([encode/1]).
-export([encrypt/2]).
-export([sign/3]).
-export([to_verifier/1]).

%% API
-export([to_public_key/1]).
-export([verify/4]).

%% Types
-type secret() :: public_key:private_key().

-export_type([secret/0]).

%%====================================================================
%% http_signature_signer callbacks
%%====================================================================

algorithm(#'DSAPrivateKey'{}) ->
	{dsa, sha};
algorithm(#'ECPrivateKey'{}) ->
	{ecdsa, sha256};
algorithm(#'RSAPrivateKey'{}) ->
	{rsa, sha256}.

decode(SecretData) ->
	case public_key:pem_decode(SecretData) of
		[PemEntry] ->
			public_key:pem_entry_decode(PemEntry);
		DecodeError ->
			erlang:error({badarg, DecodeError})
	end.

decrypt(SecretPass, EncryptedData) ->
	case public_key:pem_decode(EncryptedData) of
		[PemEntry] ->
			Password = unicode:characters_to_list(SecretPass),
			public_key:pem_entry_decode(PemEntry, Password);
		DecodeError ->
			erlang:error({badarg, DecodeError})
	end.

encode(DSAPrivateKey=#'DSAPrivateKey'{}) ->
	PemEntry = public_key:pem_entry_encode('DSAPrivateKey', DSAPrivateKey),
	public_key:pem_encode([PemEntry]);
encode(ECPrivateKey=#'ECPrivateKey'{}) ->
	PemEntry = public_key:pem_entry_encode('ECPrivateKey', ECPrivateKey),
	public_key:pem_encode([PemEntry]);
encode(RSAPrivateKey=#'RSAPrivateKey'{}) ->
	PemEntry = public_key:pem_entry_encode('RSAPrivateKey', RSAPrivateKey),
	public_key:pem_encode([PemEntry]).

encrypt(SecretPass, DSAPrivateKey=#'DSAPrivateKey'{}) ->
	encrypt_key(SecretPass, 'DSAPrivateKey', DSAPrivateKey);
encrypt(SecretPass, ECPrivateKey=#'ECPrivateKey'{}) ->
	encrypt_key(SecretPass, 'ECPrivateKey', ECPrivateKey);
encrypt(SecretPass, RSAPrivateKey=#'RSAPrivateKey'{}) ->
	encrypt_key(SecretPass, 'RSAPrivateKey', RSAPrivateKey).

sign(Message, HashType, PrivateKey) ->
	public_key:sign(Message, HashType, PrivateKey).

to_verifier(Secret) ->
	Public = to_public_key(Secret),
	PublicData = http_signature_public_key:public_encode(Public),
	http_signature_verifier:from_data({http_signature_public_key, PublicData}).

%%====================================================================
%% API functions
%%====================================================================

to_public_key(#'DSAPrivateKey'{y=Y, p=P, q=Q, g=G}) ->
	DSAPublicKey = {Y, #'Dss-Parms'{p=P, q=Q, g=G}},
	{DSAPublicKey, []};
to_public_key(#'ECPrivateKey'{parameters=ECParameters, publicKey=Octets0}) ->
	Octets = case Octets0 of
		{_, Octets1} ->
			Octets1;
		_ ->
			Octets0
	end,
	ECPoint = #'ECPoint'{point=Octets},
	ECPublicKey = {ECPoint, ECParameters},
	{ECPublicKey, []};
to_public_key(#'RSAPrivateKey'{modulus=Modulus, publicExponent=PublicExponent}) ->
	RSAPublicKey = #'RSAPublicKey'{modulus=Modulus, publicExponent=PublicExponent},
	{RSAPublicKey, []}.

verify(Message, HashType, Signature, PrivateKey) ->
	http_signature_public_key:verify(Message, HashType, Signature, to_public_key(PrivateKey)).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
encrypt_key(SecretPass, PrivateKeyType, PrivateKey) ->
	CipherInfo = {"DES-EDE3-CBC", crypto:rand_bytes(8)},
	Password = binary_to_list(iolist_to_binary(SecretPass)),
	PemEntry = public_key:pem_entry_encode(PrivateKeyType, PrivateKey, {CipherInfo, Password}),
	public_key:pem_encode([PemEntry]).
