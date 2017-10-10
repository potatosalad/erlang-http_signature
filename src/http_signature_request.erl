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
-module(http_signature_request).

-include("http_signature_utils.hrl").

%% Types
-type t() :: #{
	'__struct__' := ?MODULE,
	method := binary(),
	path := binary(),
	headers := #{ binary() => binary() }
}.

-export_type([t/0]).

%% Elixir API
-export(['__struct__'/0]).
-export(['__struct__'/1]).
%% API
-export([new/3]).
-export([sign/2]).
-export([sign/3]).
-export([validate/2]).
-export([verify/2]).

%%%===================================================================
%%% Elixir API functions
%%%===================================================================

'__struct__'() ->
	#{
		'__struct__' => ?MODULE,
		method => nil,
		path => nil,
		headers => nil
	}.

'__struct__'(List) when is_list(List) ->
	'__struct__'(maps:from_list(List));
'__struct__'(Map) when is_map(Map) ->
	maps:fold(fun maps:update/3, '__struct__'(), Map).

%%%===================================================================
%%% API functions
%%%===================================================================

new(Method0, Path0, Headers0) ->
	Method = lowercase_binary(Method0),
	Path = lowercase_binary(Path0),
	Headers = lowercase_keys(Headers0),
	'__struct__'(#{ method => Method, path => Path, headers => Headers }).

sign(Request = #{ '__struct__' := ?MODULE }, Signer = #{ '__struct__' := http_signature_signer }) ->
	sign(Request, Signer, #{}).

sign(Request0 = #{
	'__struct__' := ?MODULE,
	method := Method,
	path := Path,
	headers := Headers0
}, Signer = #{
	'__struct__' := http_signature_signer,
	algorithm := Algorithm,
	headers := HeadersParameter,
	key := Key
}, Extra) when is_map(Extra) ->
	Headers1 =
		case maps:is_key(<<"x-date">>, Headers0) of
			true ->
				Headers0;
			false ->
				case maps:is_key(<<"date">>, Headers0) of
					true ->
						Headers0;
					false ->
						maps:put(<<"date">>, http_signature_date:rfc1123(), Headers0)
				end
		end,
	SignatureString = http_signature_string:new(Method, Path, Headers1, HeadersParameter),
	Authorization = http_signature_authorization:new(#{
		algorithm => Algorithm,
		extra => Extra,
		headers => HeadersParameter,
		key_id => http_signature_key:id(Key),
		signature => http_signature_signer:sign(Signer, SignatureString)
	}),
	AuthorizationHeader = http_signature_authorization:encode(Authorization),
	Headers2 = maps:put(<<"authorization">>, AuthorizationHeader, Headers1),
	Request1 = Request0#{ headers := Headers2 },
	Request1.

validate(Request = #{
	'__struct__' := ?MODULE,
	headers := Headers
}, Verifier0) ->
	case Headers of
		#{ <<"authorization">> := AuthorizationHeader } ->
			case http_signature_authorization:try_decode(AuthorizationHeader) of
				{ok, Authorization = #{ headers := HeadersParameter }} ->
					Verifier =
						case Verifier0 of
							_ when is_function(Verifier0, 2) ->
								Verifier0(Request, Authorization);
							#{ '__struct__' := http_signature_verifier } ->
								Verifier0;
							#{ '__struct__' := http_signature_signer } ->
								http_signature_signer:to_verifier(Verifier0)
						end,
					case Verifier of
						#{ '__struct__' := http_signature_verifier } ->
							{http_signature_verifier:validate(Verifier, HeadersParameter), Authorization, Verifier};
						_ ->
							{false, Authorization, Verifier}
					end;
				_ ->
					{false, nil, Verifier0}
			end;
		_ ->
			{false, nil, Verifier0}
	end.

verify(Request = #{
	'__struct__' := ?MODULE,
	method := Method,
	path := Path,
	headers := Headers
}, Verifier0) ->
	case validate(Request, Verifier0) of
		{true, #{ algorithm := Algorithm, headers := HeadersParameter, signature := Signature }, Verifier} ->
			SignatureString = http_signature_string:new(Method, Path, Headers, HeadersParameter),
			http_signature_verifier:verify(Verifier, Algorithm, Signature, SignatureString);
		{false, _, _} ->
			false
	end.

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
lowercase_binary(T) ->
	?INLINE_LOWERCASE_BC(to_string(T)).

%% @private
lowercase_keys(Map) when is_map(Map) ->
	maps:fold(fun lowercase_keys_folder/3, maps:new(), Map);
lowercase_keys(List) when is_list(List) ->
	lowercase_keys(maps:from_list(List)).

%% @private
lowercase_keys_folder(Key, Val, Acc) ->
	maps:put(?INLINE_LOWERCASE_BC(to_string(Key)), to_string(Val), Acc).

%% @private
to_string(B) when is_binary(B) ->
	B;
to_string(A) when is_atom(A) ->
	erlang:atom_to_binary(A, unicode);
to_string(L) when is_list(L) ->
	try
		unicode:characters_to_binary(L)
	catch _:_ ->
		erlang:iolist_to_binary(L)
	end.
