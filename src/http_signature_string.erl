%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <andrew@pixid.com>
%%% @copyright 2014-2017, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  07 Oct 2017 by Andrew Bennett <andrew@pixid.com>
%%%-------------------------------------------------------------------
-module(http_signature_string).

-include("http_signature_utils.hrl").

%% Types
-type t() :: binary().

-export_type([t/0]).

%% API
-export([new/4]).

%%%===================================================================
%%% API functions
%%%===================================================================

new(Method0, Path0, Headers0, HeadersParameter0) ->
	Method = lowercase_binary(Method0),
	Path = lowercase_binary(Path0),
	Headers = lowercase_keys(Headers0),
	HeadersParameter = lowercase_list(HeadersParameter0),
	build(Method, Path, Headers, HeadersParameter).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
build(Method, Path, Headers = #{}, HeadersParameter = [_ | _])
		when is_binary(Method)
		andalso is_binary(Path) ->
	<< $\n, SignatureString/binary >> = <<
		<<
			(case Header of
				<<"(request-target)">> ->
					<< $\n, Header/binary, $:, $\s, Method/binary, $\s, Path/binary >>;
				_ ->
					<< $\n, Header/binary, $:, $\s, (maps:get(Header, Headers))/binary >>
			end)/binary
		>> || Header <- HeadersParameter
	>>,
	SignatureString;
build(Method, Path, Headers = #{ <<"x-date">> := _ }, []) ->
	build(Method, Path, Headers, [<<"x-date">>]);
build(Method, Path, Headers = #{ <<"date">> := _ }, []) ->
	build(Method, Path, Headers, [<<"date">>]).

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
lowercase_list(List) when is_list(List) ->
	[lowercase_binary(Element) || Element <- List].

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
