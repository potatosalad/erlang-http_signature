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
-module(http_signature_authorization).

-include("http_signature_utils.hrl").

%% Types
-type t() :: #{
	'__struct__' := ?MODULE,
	algorithm := http_signature_algorithm:algorithm(),
	extra := #{ binary() => binary() },
	headers := [binary()],
	key_id := binary(),
	signature := binary()
}.

-export_type([t/0]).

%% Elixir API
-export(['__struct__'/0]).
-export(['__struct__'/1]).
%% API
-export([new/0]).
-export([new/1]).
-export([decode/1]).
-export([try_decode/1]).
-export([encode/1]).

%%%===================================================================
%%% Elixir API functions
%%%===================================================================

'__struct__'() ->
	#{
		'__struct__' => ?MODULE,
		algorithm => nil,
		extra => #{},
		headers => [],
		key_id => nil,
		signature => nil
	}.

'__struct__'(List) when is_list(List) ->
	'__struct__'(maps:from_list(List));
'__struct__'(Map) when is_map(Map) ->
	maps:fold(fun maps:update/3, '__struct__'(), Map).

%%%===================================================================
%%% API functions
%%%===================================================================

new() ->
	new(#{}).

new(Enumerable) ->
	'__struct__'(Enumerable).

decode(Authorization) when is_binary(Authorization) ->
	case parse_auth(Authorization) of
		{<<"signature">>, AuthParams} ->
			decode_params(AuthParams);
		{Scheme, _} ->
			?http_signature_throw({unsupported_authorization_scheme, Scheme}, "Unsupported authorization scheme: ~s", [Scheme])
	end.

try_decode(Authorization) when is_binary(Authorization) ->
	try decode(Authorization) of
		Struct = #{ '__struct__' := ?MODULE } ->
			{ok, Struct}
	catch
		Class:Reason ->
			{Class, Reason}
	end.

encode(#{ '__struct__' := ?MODULE, algorithm := Algorithm, extra := Extra, headers := Headers, key_id := KeyId, signature := Signature }) ->
	Head = <<"=\"">>,
	Tail = <<"\",">>,
	Values0 = #{
		<<"algorithm">> => Algorithm,
		<<"keyId">> => KeyId,
		<<"signature">> => base64:encode(Signature)
	},
	Values1 =
		case Headers of
			[] ->
				Values0;
			_ ->
				<< $\s, HeadersValue/binary >> = << << $\s, Header/binary >> || Header <- Headers >>,
				maps:put(<<"headers">>, HeadersValue, Values0)
		end,
	Keys0 = ordsets:from_list(maps:keys(Values1)),
	Keys1 = ordsets:from_list(maps:keys(Extra)),
	Keys = ordsets:union(Keys0, Keys1),
	Values = maps:merge(Extra, Values1),
	erlang:iolist_to_binary([
		<<"Signature ">>,
		encode_params(ordsets:to_list(Keys), Values, Head, Tail, [])
	]).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
decode_params(AuthParams = #{
	<<"algorithm">> := Algorithm,
	<<"keyid">> := KeyId,
	<<"signature">> := Signature0
}) ->
	% Algorithm = http_signature_algorithm:from_binary(Algorithm0),
	Signature = base64:decode(Signature0),
	Headers =
		case AuthParams of
			#{ <<"headers">> := Headers0 } ->
				parse_auth_headers(Headers0);
			_ ->
				[]
		end,
	new(#{
		algorithm => Algorithm,
		extra => maps:without([<<"algorithm">>, <<"headers">>, <<"keyid">>, <<"signature">>], AuthParams),
		headers => Headers,
		key_id => KeyId,
		signature => Signature
	});
decode_params(AuthParams) ->
	?http_signature_throw({unsupported_signature_params, AuthParams}, "Unsupported signature params: ~p", [AuthParams]).

%% @private
encode_params([Key | Keys = [_ | _]], Values, Head, Tail, Acc) ->
	Value = maps:get(Key, Values),
	Item = [Key, Head, Value, Tail],
	encode_params(Keys, Values, Head, Tail, [Item | Acc]);
encode_params([Key], Values, Head, Tail, Acc) ->
	Value = maps:get(Key, Values),
	Item = [Key, Head, Value, $"],
	encode_params([], Values, Head, Tail, [Item | Acc]);
encode_params([], _Values, _Head, _Tail, Acc) ->
	lists:reverse(Acc).

%% @private
parse_auth(Authorization) ->
	parse_auth_scheme(Authorization, <<>>).

%% @private
parse_auth_headers(Headers) ->
	[Header || Header <- binary:split(Headers, << $\s >>, [global, trim]), Header =/= <<>>].

%% @private
parse_auth_scheme(<< $\s, Rest/binary >>, Scheme) ->
	parse_auth_params(Rest, Scheme, #{});
parse_auth_scheme(<< C, Rest/binary >>, Scheme) ->
	parse_auth_scheme(Rest, << Scheme/binary, C >>);
parse_auth_scheme(<<>>, Scheme) ->
	{?INLINE_LOWERCASE_BC(Scheme), #{}}.

%% @private
parse_auth_params(<< $\s, Rest/binary >>, Scheme, Params) ->
	parse_auth_params(Rest, Scheme, Params);
parse_auth_params(<< C, Rest/binary >>, Scheme, Params) ->
	parse_auth_params_key(Rest, Scheme, Params, << C >>);
parse_auth_params(<<>>, Scheme, Params) ->
	{?INLINE_LOWERCASE_BC(Scheme), Params}.

%% @private
parse_auth_params_key(<< $=, Rest/binary >>, Scheme, Params, Key) ->
	case Rest of
		<< $", NewRest/binary >> ->
			parse_auth_params_val(NewRest, Scheme, Params, Key, <<>>);
		_ ->
			{?INLINE_LOWERCASE_BC(Scheme), Params}
	end;
parse_auth_params_key(<< C, Rest/binary >>, Scheme, Params, Key) ->
	parse_auth_params_key(Rest, Scheme, Params, << Key/binary, C >>);
parse_auth_params_key(<<>>, Scheme, Params, _Key) ->
	{?INLINE_LOWERCASE_BC(Scheme), Params}.

%% @private
parse_auth_params_val(<< $", Rest/binary >>, Scheme, Params, Key, Val) ->
	LKey = ?INLINE_LOWERCASE_BC(Key),
	case Rest of
		<< $,, NewRest/binary >> ->
			parse_auth_params_key(NewRest, Scheme, Params#{ LKey => Val }, <<>>);
		_ ->
			{?INLINE_LOWERCASE_BC(Scheme), Params#{ LKey => Val }}
	end;
parse_auth_params_val(<< C, Rest/binary >>, Scheme, Params, Key, Val) ->
	parse_auth_params_val(Rest, Scheme, Params, Key, << Val/binary, C >>);
parse_auth_params_val(<<>>, Scheme, Params, _Key, _Val) ->
	{?INLINE_LOWERCASE_BC(Scheme), Params}.
