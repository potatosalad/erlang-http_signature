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
-module(http_signature).

%% API
-export([sign/4]).
-export([sign/5]).
-export([verify/4]).

%% Utility API
-export([constant_time_compare/2]).

%%====================================================================
%% API functions
%%====================================================================

sign(Signer, Method, Path, Headers) ->
	sign(Signer, Method, Path, Headers, #{}).

sign(Signer, Method, Path, Headers, Extra) ->
	Request = http_signature_request:new(Method, Path, Headers),
	http_signature_request:sign(Request, Signer, Extra).

verify(Verifier, Method, Path, Headers) ->
	Request = http_signature_request:new(Method, Path, Headers),
	http_signature_request:verify(Request, Verifier).

%%====================================================================
%% Utility API functions
%%====================================================================

constant_time_compare(<<>>, _) ->
	false;
constant_time_compare(_, <<>>) ->
	false;
constant_time_compare(A, B)
		when is_binary(A) andalso is_binary(B)
		andalso (byte_size(A) =/= byte_size(B)) ->
	false;
constant_time_compare(A, B)
		when is_binary(A) andalso is_binary(B)
		andalso (byte_size(A) =:= byte_size(B)) ->
	constant_time_compare(A, B, 0).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
constant_time_compare(<< AH, AT/binary >>, << BH, BT/binary >>, R) ->
	constant_time_compare(AT, BT, R bor (BH bxor AH));
constant_time_compare(<<>>, <<>>, R) ->
	R =:= 0.
