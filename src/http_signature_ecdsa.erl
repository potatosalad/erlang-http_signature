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
-module(http_signature_ecdsa).
-behaviour(http_signature_algorithm).

-include("http_signature_utils.hrl").
-include_lib("public_key/include/public_key.hrl").

%% http_signature_algorithm callbacks
-export([default_sign_algorithm/1]).
-export([encode_pem/1]).
-export([encode_pem/2]).
-export([generate_key/1]).
-export([sign/3]).
-export([verify/4]).

%%%===================================================================
%%% http_signature_algorithm callbacks
%%%===================================================================

default_sign_algorithm(#'ECPrivateKey'{parameters=ECParameters}) ->
	NamedCurve = ec_parameters_to_named_curve(ECParameters),
	Size = ec_named_curve_to_size(NamedCurve),
	case Size of
		_ when Size =< 32 -> <<"ecdsa-sha256">>;
		_ when Size =< 48 -> <<"ecdsa-sha384">>;
		_ -> <<"ecdsa-sha512">>
	end.

encode_pem(ECPrivateKey = #'ECPrivateKey'{}) ->
	PEMEntry = http_signature_public_key:pem_entry_encode('ECPrivateKey', ECPrivateKey),
	http_signature_public_key:pem_encode([PEMEntry]);
encode_pem(ECPublicKey = {#'ECPoint'{}, _}) ->
	PEMEntry = http_signature_public_key:pem_entry_encode('SubjectPublicKeyInfo', ECPublicKey),
	http_signature_public_key:pem_encode([PEMEntry]).

encode_pem(ECPrivateKey = #'ECPrivateKey'{}, Password) ->
	CipherInfo = {"AES-128-CBC", crypto:strong_rand_bytes(16)},
	PasswordString = erlang:binary_to_list(erlang:iolist_to_binary(Password)),
	PEMEntry = http_signature_public_key:pem_entry_encode('ECPrivateKey', ECPrivateKey, {CipherInfo, PasswordString}),
	http_signature_public_key:pem_encode([PEMEntry]).

generate_key(#'ECPrivateKey'{ parameters = P }) ->
	generate_key(P);
generate_key({#'ECPoint'{}, P}) ->
	generate_key(P);
generate_key(ECParameters = #'ECParameters'{}) ->
	public_key:generate_key(ECParameters);
generate_key(NamedCurve) when is_atom(NamedCurve) ->
	generate_key({namedCurve, pubkey_cert_records:namedCurves(NamedCurve)});
generate_key(NamedCurve) when is_binary(NamedCurve) ->
	generate_key(http_signature_public_key:ec_domain_parameters_to_named_curve(NamedCurve));
generate_key({namedCurve, NamedCurve}) when is_atom(NamedCurve) orelse is_binary(NamedCurve) ->
	generate_key(NamedCurve);
generate_key(NamedCurve = {namedCurve, _}) ->
	public_key:generate_key(NamedCurve).

sign(ECPrivateKey=#'ECPrivateKey'{parameters=ECParameters}, Algorithm, Message) ->
	DigestType = algorithm_to_digest_type(Algorithm),
	DERSignature = public_key:sign(Message, DigestType, ECPrivateKey),
	#'ECDSA-Sig-Value'{ r = R, s = S } = public_key:der_decode('ECDSA-Sig-Value', DERSignature),
	NamedCurve = ec_parameters_to_named_curve(ECParameters),
	Size = ec_named_curve_to_size(NamedCurve),
	RBin = int_to_bin(R),
	SBin = int_to_bin(S),
	RPad = pad(RBin, Size),
	SPad = pad(SBin, Size),
	Signature = << RPad/binary, SPad/binary >>,
	Signature.

verify(ECPublicKey={#'ECPoint'{}, _}, Algorithm, Signature, Message) ->
	DigestType = algorithm_to_digest_type(Algorithm),
	SignatureLen = byte_size(Signature),
	{RBin, SBin} = split_binary(Signature, (SignatureLen div 2)),
	R = crypto:bytes_to_integer(RBin),
	S = crypto:bytes_to_integer(SBin),
	DERSignature = public_key:der_encode('ECDSA-Sig-Value', #'ECDSA-Sig-Value'{ r = R, s = S }),
	public_key:verify(Message, DigestType, DERSignature, ECPublicKey).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
algorithm_to_digest_type(Algorithm) ->
	case Algorithm of
		<<"ecdsa-sha1">> -> sha;
		<<"ecdsa-sha224">> -> sha224;
		<<"ecdsa-sha256">> -> sha256;
		<<"ecdsa-sha384">> -> sha384;
		<<"ecdsa-sha512">> -> sha512;
		_ -> ?http_signature_throw({bad_algorithm, Algorithm}, "Bad algorithm for ECDSA key: ~s", [Algorithm])
	end.

%% @private
ec_named_curve_to_size(secp256r1) -> 32;
ec_named_curve_to_size(secp384r1) -> 48;
ec_named_curve_to_size(secp521r1) -> 66;
ec_named_curve_to_size(sect163k1) -> 21;
ec_named_curve_to_size(secp192r1) -> 24;
ec_named_curve_to_size(secp224r1) -> 28;
ec_named_curve_to_size(sect233k1) -> 30;
ec_named_curve_to_size(sect233r1) -> 30;
ec_named_curve_to_size(sect283k1) -> 36;
ec_named_curve_to_size(sect409k1) -> 52;
ec_named_curve_to_size(sect409r1) -> 52;
ec_named_curve_to_size(sect571k1) -> 72.

%% @private
ec_parameters_to_named_curve({namedCurve, P}) ->
	pubkey_cert_records:namedCurves(P);
ec_parameters_to_named_curve(P) ->
	P.

%% @private
int_to_bin(X) when X < 0 -> int_to_bin_neg(X, []);
int_to_bin(X) -> int_to_bin_pos(X, []).

%% @private
int_to_bin_pos(0,Ds=[_|_]) ->
	list_to_binary(Ds);
int_to_bin_pos(X,Ds) ->
	int_to_bin_pos(X bsr 8, [(X band 255)|Ds]).

%% @private
int_to_bin_neg(-1, Ds=[MSB|_]) when MSB >= 16#80 ->
	list_to_binary(Ds);
int_to_bin_neg(X,Ds) ->
	int_to_bin_neg(X bsr 8, [(X band 255)|Ds]).

%% @private
pad(Bin, Size) when byte_size(Bin) =:= Size ->
	Bin;
pad(Bin, Size) when byte_size(Bin) < Size ->
	pad(<< 0, Bin/binary >>, Size).
