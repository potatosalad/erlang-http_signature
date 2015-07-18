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
-module(http_signature_public_key_ecdh).

-include("http_signature.hrl").

-include_lib("public_key/include/public_key.hrl").

%% API
-export([public_decode/1]).
-export([public_encode/1]).

%% Utility API
-export([domain_parameters_to_named_curve/1]).
-export([named_curve_to_domain_parameters/1]).
-export([named_curve_to_signature_algorithm/1]).
-export([signature_algorithm_to_named_curve/1]).

%%====================================================================
%% API functions
%%====================================================================

public_decode({{SignatureAlgorithm, <<
		SignatureAlgorithmSize:32/big-unsigned-integer,
		SignatureAlgorithm:SignatureAlgorithmSize/binary,
		DomainParametersSize:32/big-unsigned-integer,
		DomainParameters:DomainParametersSize/binary,
		OctetsSize:32/big-unsigned-integer,
		Octets:OctetsSize/binary >>}, Comments}) ->
	ECPoint = #'ECPoint'{point=Octets},
	CurveId = domain_parameters_to_named_curve(DomainParameters),
	Parameters = pubkey_cert_records:namedCurves(CurveId),
	ECParameters = {namedCurve, Parameters},
	ECPublicKey = {ECPoint, ECParameters},
	{ECPublicKey, Comments}.

public_encode({{#'ECPoint'{point=Octets}, {namedCurve, Parameters}}, Comments}) ->
	CurveId = pubkey_cert_records:namedCurves(Parameters),
	DomainParameters = named_curve_to_domain_parameters(CurveId),
	SignatureAlgorithm = named_curve_to_signature_algorithm(CurveId),
	SignatureAlgorithmSize = byte_size(SignatureAlgorithm),
	DomainParametersSize = byte_size(DomainParameters),
	OctetsSize = byte_size(Octets),
	ECPublicKey = {SignatureAlgorithm, <<
		SignatureAlgorithmSize:32/big-unsigned-integer,
		SignatureAlgorithm:SignatureAlgorithmSize/binary,
		DomainParametersSize:32/big-unsigned-integer,
		DomainParameters:DomainParametersSize/binary,
		OctetsSize:32/big-unsigned-integer,
		Octets:OctetsSize/binary
	>>},
	{ECPublicKey, Comments}.

%%====================================================================
%% Utility API functions
%%====================================================================

named_curve_to_signature_algorithm(CurveId) ->
	<< "ecdsa-sha2-", (named_curve_to_domain_parameters(CurveId))/binary >>.

domain_parameters_to_named_curve(<<"nistp256">>) -> secp256r1;
domain_parameters_to_named_curve(<<"nistp384">>) -> secp384r1;
domain_parameters_to_named_curve(<<"nistp521">>) -> secp521r1;
domain_parameters_to_named_curve(<<"nistk163">>) -> sect163k1;
domain_parameters_to_named_curve(<<"nistp192">>) -> secp192r1;
domain_parameters_to_named_curve(<<"nistp224">>) -> secp224r1;
domain_parameters_to_named_curve(<<"nistk233">>) -> sect233k1;
domain_parameters_to_named_curve(<<"nistb233">>) -> sect233r1;
domain_parameters_to_named_curve(<<"nistk283">>) -> sect283k1;
domain_parameters_to_named_curve(<<"nistk409">>) -> sect409k1;
domain_parameters_to_named_curve(<<"nistb409">>) -> sect409r1;
domain_parameters_to_named_curve(<<"nistt571">>) -> sect571k1.

named_curve_to_domain_parameters(secp256r1) -> <<"nistp256">>;
named_curve_to_domain_parameters(secp384r1) -> <<"nistp384">>;
named_curve_to_domain_parameters(secp521r1) -> <<"nistp521">>;
named_curve_to_domain_parameters(sect163k1) -> <<"nistk163">>;
named_curve_to_domain_parameters(secp192r1) -> <<"nistp192">>;
named_curve_to_domain_parameters(secp224r1) -> <<"nistp224">>;
named_curve_to_domain_parameters(sect233k1) -> <<"nistk233">>;
named_curve_to_domain_parameters(sect233r1) -> <<"nistb233">>;
named_curve_to_domain_parameters(sect283k1) -> <<"nistk283">>;
named_curve_to_domain_parameters(sect409k1) -> <<"nistk409">>;
named_curve_to_domain_parameters(sect409r1) -> <<"nistb409">>;
named_curve_to_domain_parameters(sect571k1) -> <<"nistt571">>.

signature_algorithm_to_named_curve(<< "ecdsa-sha2-", DomainParameters/binary >>) ->
	domain_parameters_to_named_curve(DomainParameters).
