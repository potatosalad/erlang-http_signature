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
-module(http_signature_signer).

%% Types
-type t() :: #{
	'__struct__' := ?MODULE,
	algorithm := binary(),
	headers := [binary()],
	key := http_signature_key:secret() | http_signature_key:shared()
}.

-export_type([t/0]).

%% Elixir API
-export(['__struct__'/0]).
-export(['__struct__'/1]).
%% API
-export([new/1]).
-export([new/2]).
-export([new/3]).
-export([sign/2]).
-export([verify/4]).
-export([to_verifier/1]).

%%%===================================================================
%%% Elixir API functions
%%%===================================================================

'__struct__'() ->
	#{
		'__struct__' => ?MODULE,
		algorithm => nil,
		headers => nil,
		key => nil
	}.

'__struct__'(List) when is_list(List) ->
	'__struct__'(maps:from_list(List));
'__struct__'(Map) when is_map(Map) ->
	maps:fold(fun maps:update/3, '__struct__'(), Map).

%%%===================================================================
%%% API functions
%%%===================================================================

new(Key=#{ '__struct__' := http_signature_key }) ->
	Algorithm = http_signature_key:default_sign_algorithm(Key),
	new(Key, Algorithm).

new(Key=#{ '__struct__' := http_signature_key }, Algorithm) ->
	new(Key, Algorithm, []).

new(Key=#{ '__struct__' := http_signature_key }, Algorithm, Headers) ->
	% Verify that we can sign and verify with this key and algorithm.
	Message = crypto:strong_rand_bytes(16),
	Signature = http_signature_key:sign(Key, Algorithm, Message),
	true = http_signature_key:verify(Key, Algorithm, Signature, Message),
	'__struct__'(#{ key => Key, algorithm => Algorithm, headers => Headers }).

sign(#{ '__struct__' := ?MODULE, key := Key, algorithm := Algorithm }, Message) ->
	http_signature_key:sign(Key, Algorithm, Message).

verify(Signer=#{ '__struct__' := ?MODULE }, Algorithm, Signature, Message) ->
	Verifier = to_verifier(Signer),
	http_signature_verifier:verify(Verifier, Algorithm, Signature, Message).

to_verifier(#{ '__struct__' := ?MODULE, key := Key, algorithm := Algorithm, headers := Headers }) ->
	http_signature_verifier:new(Key, [Algorithm], Headers).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------
