%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
-module(http_signature_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("public_key/include/public_key.hrl").

%% ct.
-export([all/0]).
-export([groups/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([init_per_group/2]).
-export([end_per_group/2]).

%% Tests.
-export([sign_and_verify/1]).
-export([sign_and_verify_request/1]).

all() ->
	[
		{group, smoke}
	].

groups() ->
	[
		{smoke, [parallel], [
			sign_and_verify,
			sign_and_verify_request
		]}
	].

init_per_suite(Config) ->
	_ = application:ensure_all_started(http_signature),
	Config.

end_per_suite(_Config) ->
	_ = application:stop(http_signature),
	ok.

init_per_group(smoke, Config) ->
	[
		{sign_and_verify, [
			{dsa, [sha]},
			{ecdsa, [sha, sha256, sha512]},
			{hmac, [sha, sha256, sha512]},
			{rsa, [sha, sha256, sha512]}
		]},
		{sign_and_verify_request, [
			{get, <<"/path">>, #{}, [{key_id, <<"key_id">>}]},
			{get, <<"/path">>, #{ <<"extra">> => <<"val">> }, [{headers, [<<"date">>, <<"extra">>]}, {key_id, <<"key_id">>}]},
			{put, <<"/path">>, #{}, [{headers, [<<"(request-target)">>, <<"x-date">>]}, {key_id, <<"key_id">>}]}
		]}
		| Config
	].

end_per_group(_Group, _Config) ->
	ok.

%%====================================================================
%% Tests
%%====================================================================

sign_and_verify(Config) ->
	Algorithms = ?config(sign_and_verify, Config),
	lists:foreach(fun sign_and_verify_all/1, Algorithms).

%% @private
sign_and_verify_all({KeyType, HashTypes}) ->
	Algorithms = [{KeyType, HashType} || HashType <- HashTypes],
	lists:foreach(fun sign_and_verify_one/1, Algorithms).

%% @private
sign_and_verify_one({KeyType, HashType}) ->
	ct:log("[~p] ~p~n", [sign_and_verify, {KeyType, HashType}]),
	{SignerSecret, SignerSecretData} = make_secret(KeyType),
	{_VerifierPublic, VerifierPublicData} = make_public(KeyType, SignerSecret),
	SignerModule = signer_module(KeyType),
	VerifierModule = verifier_module(KeyType),
	Signer = http_signature_signer:from_data({SignerModule, SignerSecretData}),
	Verifier = http_signature_verifier:from_data({VerifierModule, VerifierPublicData}),
	Verifier = http_signature_signer:to_verifier(Signer),
	SignerSecretPass = base64:encode(crypto:rand_bytes(crypto:rand_uniform(8, 128))),
	{SignerModule, SignerSecretDataEncrypted} = http_signature_signer:to_data(SignerSecretPass, Signer),
	Signer = http_signature_signer:from_data(SignerSecretPass, {SignerModule, SignerSecretDataEncrypted}),
	Message = crypto:rand_bytes(crypto:rand_uniform(8, 1024)),
	Signature = http_signature_signer:sign(Message, Signer),
	true = http_signature_signer:verify(Message, Signature, Signer),
	Algorithm = http_signature_signer:algorithm(Signer),
	true = http_signature_verifier:verify(Message, Algorithm, Signature, Verifier),
	NewSigner = http_signature_signer:algorithm({KeyType, HashType}, Signer),
	NewSignature = http_signature_signer:sign(Message, NewSigner),
	true = http_signature_signer:verify(Message, NewSignature, NewSigner),
	NewAlgorithm = http_signature_signer:algorithm(NewSigner),
	true = http_signature_verifier:verify(Message, NewAlgorithm, NewSignature, Verifier),
	ok.

sign_and_verify_request(Config) ->
	Algorithms = ?config(sign_and_verify, Config),
	Requests = [{Request, Algorithms} || Request <- ?config(sign_and_verify_request, Config)],
	lists:foreach(fun sign_and_verify_request_all/1, Requests).

%% @private
sign_and_verify_request_all({Request, Algorithms}) ->
	Requests = lists:flatten([begin
		[{Request, {KeyType, HashType}} || HashType <- HashTypes]
	end || {KeyType, HashTypes} <- Algorithms]),
	lists:foreach(fun sign_and_verify_request_one/1, Requests).

%% @private
sign_and_verify_request_one({Request={M, P, H, O}, {KeyType, HashType}}) ->
	ct:log("[~p] ~p~n", [sign_and_verify_request, {Request, {KeyType, HashType}}]),
	{SignerSecret, SignerSecretData} = make_secret(KeyType),
	{_VerifierPublic, VerifierPublicData} = make_public(KeyType, SignerSecret),
	SignerModule = signer_module(KeyType),
	VerifierModule = verifier_module(KeyType),
	Signer = http_signature_signer:algorithm({KeyType, HashType},
		http_signature_signer:from_data({SignerModule, SignerSecretData})),
	Verifier = http_signature_verifier:from_data({VerifierModule, VerifierPublicData}),
	{Method, Path, Headers} = http_signature:sign_request(M, P, H, O, Signer),
	true = http_signature:verify_request(Method, Path, Headers, [], Verifier),
	ok.

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
gen_ec(CurveId) ->
	public_key:generate_key({namedCurve, pubkey_cert_records:namedCurves(CurveId)}).

%% @private
gen_private_key(dsa) ->
	erl_make_certs:gen_dsa(128, 20);
gen_private_key(ecdsa) ->
	{gen_ec(secp256r1), undefined};
gen_private_key(rsa) ->
	erl_make_certs:gen_rsa(64).

%% @private
make_public(hmac, {http_signature_hmac, Key}) ->
	{{http_signature_hmac, Key}, Key};
make_public(dsa, #'DSAPrivateKey'{y=Y, p=P, q=Q, g=G}) ->
	DSAPublicKey = {Y, #'Dss-Parms'{p=P, q=Q, g=G}},
	{DSAPublicKey, bin_public_key(DSAPublicKey)};
make_public(ecdsa, #'ECPrivateKey'{parameters=ECParameters, publicKey=Octets0}) ->
	Octets = case Octets0 of
		{_, Octets1} ->
			Octets1;
		_ ->
			Octets0
	end,
	ECPoint = #'ECPoint'{point=Octets},
	ECPublicKey = {ECPoint, ECParameters},
	{ECPublicKey, bin_public_key(ECPublicKey)};
make_public(rsa, #'RSAPrivateKey'{modulus=Modulus, publicExponent=PublicExponent}) ->
	RSAPublicKey = #'RSAPublicKey'{modulus=Modulus, publicExponent=PublicExponent},
	{RSAPublicKey, bin_public_key(RSAPublicKey)}.

%% @private
make_secret(hmac) ->
	Key = crypto:rand_bytes(crypto:rand_uniform(64, 256)),
	{{http_signature_hmac, Key}, Key};
make_secret(KeyType) ->
	{Key, _} = gen_private_key(KeyType),
	{Key, bin_private_key(Key)}.

%% @private
signer_module(hmac) ->
	http_signature_hmac;
signer_module(_) ->
	http_signature_private_key.

%% @private
verifier_module(hmac) ->
	http_signature_hmac;
verifier_module(_) ->
	http_signature_public_key.

%% @private
bin_public_key(PublicKey={_, #'Dss-Parms'{}}) ->
	public_key:ssh_encode([{PublicKey, []}], auth_keys);
bin_public_key(PublicKey=#'RSAPublicKey'{}) ->
	public_key:ssh_encode([{PublicKey, []}], auth_keys);
bin_public_key({#'ECPoint'{point=Octets}, {namedCurve, Parameters}}) ->
	{SignatureAlgorithm, DomainParameters} = case pubkey_cert_records:namedCurves(Parameters) of
		secp256r1 ->
			{<<"ecdsa-sha2-nistp256">>, <<"nistp256">>};
		secp384r1 ->
			{<<"ecdsa-sha2-nistp384">>, <<"nistp384">>};
		secp521r1 ->
			{<<"ecdsa-sha2-nistp521">>, <<"nistp521">>};
		sect163k1 ->
			{<<"ecdsa-sha2-nistk163">>, <<"nistk163">>};
		secp192r1 ->
			{<<"ecdsa-sha2-nistp192">>, <<"nistp192">>};
		secp224r1 ->
			{<<"ecdsa-sha2-nistp224">>, <<"nistp224">>};
		sect233k1 ->
			{<<"ecdsa-sha2-nistk233">>, <<"nistk233">>};
		sect233r1 ->
			{<<"ecdsa-sha2-nistb233">>, <<"nistb233">>};
		sect283k1 ->
			{<<"ecdsa-sha2-nistk283">>, <<"nistk283">>};
		sect409k1 ->
			{<<"ecdsa-sha2-nistk409">>, <<"nistk409">>};
		sect409r1 ->
			{<<"ecdsa-sha2-nistb409">>, <<"nistb409">>};
		sect571k1 ->
			{<<"ecdsa-sha2-nistt571">>, <<"nistt571">>}
	end,
	SignatureAlgorithmSize = byte_size(SignatureAlgorithm),
	DomainParametersSize = byte_size(DomainParameters),
	OctetsSize = byte_size(Octets),
	PublicKey = <<
		SignatureAlgorithmSize:32/big-unsigned-integer,
		SignatureAlgorithm:SignatureAlgorithmSize/binary,
		DomainParametersSize:32/big-unsigned-integer,
		DomainParameters:DomainParametersSize/binary,
		OctetsSize:32/big-unsigned-integer,
		Octets:OctetsSize/binary
	>>,
	<<
		SignatureAlgorithm/binary, $\s,
		(base64:encode(PublicKey))/binary, $\n
	>>.

%% @private
bin_private_key(DSAPrivateKey=#'DSAPrivateKey'{}) ->
	PemEntry = public_key:pem_entry_encode('DSAPrivateKey', DSAPrivateKey),
	public_key:pem_encode([PemEntry]);
bin_private_key(ECPrivateKey=#'ECPrivateKey'{}) ->
	PemEntry = public_key:pem_entry_encode('ECPrivateKey', ECPrivateKey),
	public_key:pem_encode([PemEntry]);
bin_private_key(RSAPrivateKey=#'RSAPrivateKey'{}) ->
	PemEntry = public_key:pem_entry_encode('RSAPrivateKey', RSAPrivateKey),
	public_key:pem_encode([PemEntry]).
