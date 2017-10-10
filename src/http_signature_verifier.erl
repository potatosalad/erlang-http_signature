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
-module(http_signature_verifier).

%% Types
-type t() :: #{
	'__struct__' := ?MODULE,
	algorithms := ordsets:ordset(binary()),
	headers := [binary()],
	key := http_signature_key:public() | http_signature_key:shared()
}.

-export_type([t/0]).

%% Elixir API
-export(['__struct__'/0]).
-export(['__struct__'/1]).
%% API
-export([new/1]).
-export([new/2]).
-export([new/3]).
-export([validate/2]).
-export([verify/4]).

%%%===================================================================
%%% Elixir API functions
%%%===================================================================

'__struct__'() ->
	#{
		'__struct__' => ?MODULE,
		algorithms => nil,
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
	new(Key, [Algorithm]).

new(Key=#{ '__struct__' := http_signature_key }, Algorithms) when is_list(Algorithms) ->
	new(Key, Algorithms, []).

new(Key=#{ '__struct__' := http_signature_key }, Algorithms, Headers) when is_list(Algorithms) andalso is_list(Headers) ->
	PublicOrSharedKey =
		case Key of
			#{ public := false, shared := true } ->
				Key;
			#{ public := false, shared := false } ->
				http_signature_key:to_public(Key);
			#{ public := true } ->
				Key
		end,
	'__struct__'(#{ key => PublicOrSharedKey, algorithms => ordsets:from_list(Algorithms), headers => ordsets:from_list(Headers) }).

validate(#{ '__struct__' := ?MODULE, headers := [<<"date">>] }, []) ->
	true;
validate(#{ '__struct__' := ?MODULE, headers := RequiredHeaders }, HeadersParameter) when is_list(HeadersParameter) ->
	Headers = maps:from_list([{Header, []} || Header <- HeadersParameter]),
	validate_required(RequiredHeaders, Headers).

verify(#{ '__struct__' := ?MODULE, key := Key, algorithms := Algorithms }, Algorithm, Signature, Message) ->
	case ordsets:is_element(Algorithm, Algorithms) of
		true ->
			http_signature_key:verify(Key, Algorithm, Signature, Message);
		false ->
			false
	end.

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
validate_required([Key | Keys], Headers) ->
	case maps:is_key(Key, Headers) of
		true ->
			validate_required(Keys, Headers);
		false ->
			false
	end;
validate_required([], _Headers) ->
	true.
