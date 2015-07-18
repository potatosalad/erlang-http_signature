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
-module(http_signature_verifier).

-include("http_signature.hrl").
-include("http_signature_signer.hrl").
-include("http_signature_verifier.hrl").

-callback public_decode(PublicData) -> Public
	when
		PublicData :: iodata(),
		Public     :: http_signature:public().
-callback public_encode(Public) -> PublicData
	when
		PublicData :: iodata(),
		Public     :: http_signature:public().
-callback verify(Message, HashType, Signature, Public) -> boolean()
	when
		Message    :: iodata(),
		HashType   :: http_signature_algorithm:hash_type(),
		Signature  :: iodata(),
		Public     :: http_signature:public().

%% API
-export([from_data/1]).
-export([from_file/1]).
-export([from_signer/1]).
-export([to_data/1]).
-export([to_file/2]).

%% Verifier API
-export([module/1]).
-export([public/1]).
-export([verify/4]).

-define(DEFAULT_VERIFIER_MODULE, http_signature_public_key).

%%====================================================================
%% API functions
%%====================================================================

from_data({Module, PublicData}) ->
	Public = Module:public_decode(PublicData),
	#http_signature_verifier{
		module = Module,
		public = Public
	};
from_data(PublicData) when is_binary(PublicData) ->
	from_data({?DEFAULT_VERIFIER_MODULE, PublicData});
from_data(Verifier=#http_signature_verifier{}) ->
	Verifier.

from_file({Module, PublicFile}) ->
	case file:read_file(PublicFile) of
		{ok, PublicData} ->
			from_data({Module, PublicData});
		ReadError ->
			erlang:error({badarg, ReadError})
	end;
from_file(PublicFile) ->
	from_file({?DEFAULT_VERIFIER_MODULE, PublicFile}).

from_signer(Signer= #http_signature_signer{}) ->
	http_signature_signer:to_verifier(Signer).

to_data(#http_signature_verifier{module=Module, public=Public}) ->
	{Module, Module:public_encode(Public)}.

to_file(PublicFile, Verifier=#http_signature_verifier{}) ->
	{_, PublicData} = to_data(Verifier),
	file:write_file(PublicFile, PublicData).

%%====================================================================
%% Verifier API functions
%%====================================================================

module(#http_signature_verifier{module=Module}) ->
	Module.

public(#http_signature_verifier{public=Public}) ->
	Public.

verify(Message, Algorithm, Signature, #http_signature_verifier{module=Module, public=Public}) ->
	Module:verify(Message, http_signature_algorithm:hash_type(Algorithm), Signature, Public).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------
