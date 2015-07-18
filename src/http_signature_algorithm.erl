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
-module(http_signature_algorithm).

-include("http_signature.hrl").

%% API
-export([supported/0]).
-export([from_binary/1]).
-export([to_binary/1]).

%% Utility API
-export([hash_type/1]).
-export([normalize/1]).

-type key_type()  :: dsa | ecdsa | hmac | rsa.
-type hash_type() :: sha | sha256 | sha512.

-export_type([key_type/0]).
-export_type([hash_type/0]).

%%====================================================================
%% API functions
%%====================================================================

supported() ->
	[
		{dsa, sha},
		{ecdsa, sha},
		{ecdsa, sha256},
		{ecdsa, sha512},
		{hmac, sha},
		{hmac, sha256},
		{hmac, sha512},
		{rsa, sha},
		{rsa, sha256},
		{rsa, sha512}
	].

from_binary(Binary) ->
	case binary:split(Binary, << $- >>) of
		[KeyType, <<"sha1">>] ->
			{
				binary_to_existing_atom(KeyType, unicode),
				sha
			};
		[KeyType, HashType] ->
			{
				binary_to_existing_atom(KeyType, unicode),
				binary_to_existing_atom(HashType, unicode)
			};
		_ ->
			erlang:error({badarg, Binary})
	end.

to_binary({KeyType, sha}) ->
	<<
		(atom_to_binary(KeyType, unicode))/binary,
		"-sha1"
	>>;
to_binary({KeyType, HashType}) ->
	<<
		(atom_to_binary(KeyType, unicode))/binary,
		$-,
		(atom_to_binary(HashType, unicode))/binary
	>>.

%%====================================================================
%% Utiltiy API functions
%%====================================================================

hash_type({_KeyType, HashType}) when is_atom(HashType) ->
	HashType;
hash_type(HashType) when is_atom(HashType) ->
	HashType;
hash_type(Algorithm) when is_binary(Algorithm) ->
	hash_type(from_binary(Algorithm)).

normalize(Algorithm = {KeyType, HashType})
		when is_atom(KeyType) andalso is_atom(HashType) ->
	Algorithm;
normalize(Algorithm) when is_binary(Algorithm) ->
	normalize(from_binary(Algorithm)).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------
