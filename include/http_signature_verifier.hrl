%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <andrew@pixid.com>
%%% @copyright 2014-2015, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  17 Jul 2015 by Andrew Bennett <andrew@pixid.com>
%%%-------------------------------------------------------------------

-ifndef(HTTP_SIGNATURE_VERIFIER_HRL).

-record(http_signature_verifier, {
	module = undefined :: undefined | module(),
	public = undefined :: undefined | http_signature:public()
}).

-define(HTTP_SIGNATURE_VERIFIER_HRL, 1).

-endif.
