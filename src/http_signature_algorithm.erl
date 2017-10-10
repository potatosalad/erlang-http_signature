%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <andrew@pixid.com>
%%% @copyright 2014-2017, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  16 Jul 2015 by Andrew Bennett <andrew@pixid.com>
%%%-------------------------------------------------------------------
-module(http_signature_algorithm).

-type algorithm() :: binary().
-type key() :: term().
-type message() :: binary().
-type signature() :: binary().

-export_type([algorithm/0]).
-export_type([key/0]).
-export_type([message/0]).
-export_type([signature/0]).

-callback default_sign_algorithm(key()) -> algorithm().
-callback encode_pem(key()) -> binary().
-optional_callbacks([encode_pem/1]).
-callback encode_pem(key(), iodata()) -> binary().
-optional_callbacks([encode_pem/2]).
-callback generate_key(term()) -> key().
-callback sign(key(), algorithm(), message()) -> signature().
-callback verify(key(), algorithm(), signature(), message()) -> boolean().
