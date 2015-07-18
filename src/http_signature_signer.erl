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
-module(http_signature_signer).

-include("http_signature.hrl").
-include("http_signature_signer.hrl").

-callback algorithm(Secret) -> http_signature:algorithm()
	when
		Secret :: http_signature:secret().
-callback decode(SecretData) -> Secret
	when
		SecretData :: iodata(),
		Secret     :: http_signature:secret().
-callback decrypt(SecretPass, SecretData) -> Secret
	when
		SecretData :: iodata(),
		SecretPass :: iodata(),
		Secret     :: http_signature:secret().
-callback encode(Secret) -> SecretData
	when
		SecretData :: iodata(),
		Secret     :: http_signature:secret().
-callback encrypt(SecretPass, Secret) -> SecretData
	when
		SecretData :: iodata(),
		SecretPass :: iodata(),
		Secret     :: http_signature:secret().
-callback sign(Message, HashType, Secret) -> binary()
	when
		Message  :: iodata(),
		HashType :: http_signature_algorithm:hash_type(),
		Secret   :: http_signature:secret().
-callback to_verifier(Secret) -> http_signature:public()
	when
		Secret :: http_signature:secret().

%% API
-export([from_data/1]).
-export([from_data/2]).
-export([from_file/1]).
-export([from_file/2]).
-export([to_data/1]).
-export([to_data/2]).
-export([to_file/2]).
-export([to_file/3]).

%% Signer API
-export([algorithm/1]).
-export([algorithm/2]).
-export([key_id/1]).
-export([key_id/2]).
-export([module/1]).
-export([secret/1]).
-export([sign/2]).
-export([sign/3]).
-export([to_verifier/1]).
-export([verify/3]).

-define(DEFAULT_SIGNER_MODULE, http_signature_private_key).

%%====================================================================
%% API functions
%%====================================================================

from_data({Module, SecretData}) ->
	Secret = Module:decode(SecretData),
	Signer = Module:algorithm(Secret),
	#http_signature_signer{
		module = Module,
		secret = Secret,
		signer = Signer
	};
from_data(SecretData) when is_binary(SecretData) ->
	from_data({?DEFAULT_SIGNER_MODULE, SecretData});
from_data(Signer=#http_signature_signer{}) ->
	Signer.

from_data(SecretPass, {Module, SecretData}) ->
	Secret = Module:decrypt(SecretPass, SecretData),
	Signer = Module:algorithm(Secret),
	#http_signature_signer{
		module = Module,
		secret = Secret,
		signer = Signer
	};
from_data(SecretPass, SecretData) when is_binary(SecretData) ->
	from_data(SecretPass, {?DEFAULT_SIGNER_MODULE, SecretData});
from_data(_SecretPass, Signer=#http_signature_signer{}) ->
	Signer.

from_file({Module, SecretFile}) ->
	case file:read_file(SecretFile) of
		{ok, SecretData} ->
			from_data({Module, SecretData});
		ReadError ->
			erlang:error({badarg, ReadError})
	end;
from_file(SecretFile) ->
	from_file({?DEFAULT_SIGNER_MODULE, SecretFile}).

from_file(SecretPass, {Module, SecretFile}) ->
	case file:read_file(SecretFile) of
		{ok, SecretData} ->
			from_data(SecretPass, {Module, SecretData});
		ReadError ->
			erlang:error({badarg, ReadError})
	end;
from_file(SecretPass, SecretFile) ->
	from_file(SecretPass, {?DEFAULT_SIGNER_MODULE, SecretFile}).

to_data(#http_signature_signer{module=Module, secret=Secret}) ->
	{Module, Module:encode(Secret)}.

to_data(SecretPass, #http_signature_signer{module=Module, secret=Secret}) ->
	{Module, Module:encrypt(SecretPass, Secret)}.

to_file(SecretFile, Signer=#http_signature_signer{}) ->
	{_, SecretData} = to_data(Signer),
	file:write_file(SecretFile, SecretData).

to_file(SecretPass, SecretFile, Signer=#http_signature_signer{}) ->
	{_, SecretData} = to_data(SecretPass, Signer),
	file:write_file(SecretFile, SecretData).

%%====================================================================
%% Signer API functions
%%====================================================================

algorithm(#http_signature_signer{signer=Algorithm}) ->
	Algorithm.

algorithm(Algorithm, Signer=#http_signature_signer{}) ->
	Signer#http_signature_signer{signer=http_signature_algorithm:normalize(Algorithm)}.

key_id(#http_signature_signer{key_id=KeyId}) ->
	KeyId.

key_id(KeyId, Signer=#http_signature_signer{}) ->
	Signer#http_signature_signer{key_id=KeyId}.

module(#http_signature_signer{module=Module}) ->
	Module.

secret(#http_signature_signer{secret=Secret}) ->
	Secret.

sign(Message, Signer=#http_signature_signer{signer=Algorithm}) ->
	sign(Message, Algorithm, Signer).

sign(Message, Algorithm, #http_signature_signer{module=Module, secret=Secret}) ->
	Module:sign(Message, http_signature_algorithm:hash_type(Algorithm), Secret).

to_verifier(#http_signature_signer{module=Module, secret=Secret}) ->
	Module:to_verifier(Secret).

verify(Message, Signature, Signer=#http_signature_signer{signer={_, HashType}}) ->
	Verifier = to_verifier(Signer),
	http_signature_verifier:verify(Message, HashType, Signature, Verifier).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------
