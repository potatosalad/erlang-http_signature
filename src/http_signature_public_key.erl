%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <andrew@pixid.com>
%%% @copyright 2014-2017, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  08 Aug 2017 by Andrew Bennett <andrew@pixid.com>
%%%-------------------------------------------------------------------
-module(http_signature_public_key).

-include_lib("public_key/include/public_key.hrl").

%% API
-export([der_decode/2]).
-export([der_encode/2]).
-export([ec_domain_parameters_to_named_curve/1]).
-export([ec_named_curve_to_domain_parameters/1]).
-export([pkcs7_pad/1]).
-export([pkcs7_unpad/1]).
-export([pem_decode/1]).
-export([pem_encode/1]).
-export([pem_entry_decode/1]).
-export([pem_entry_decode/2]).
-export([pem_entry_encode/2]).
-export([pem_entry_encode/3]).
-export([ssh_decode/2]).
-export([ssh_encode/2]).

%%%===================================================================
%%% API functions
%%%===================================================================

der_decode(ASN1Type, DER) when is_atom(ASN1Type) andalso is_binary(DER) ->
	public_key:der_decode(ASN1Type, DER).

der_encode(ASN1Type, Entity) when is_atom(ASN1Type) ->
	public_key:der_encode(ASN1Type, Entity).

ec_domain_parameters_to_named_curve(P) ->
	case P of
		<<"nistp256">> -> secp256r1;
		<<"nistp384">> -> secp384r1;
		<<"nistp521">> -> secp521r1;
		<<"nistk163">> -> sect163k1;
		<<"nistp192">> -> secp192r1;
		<<"nistp224">> -> secp224r1;
		<<"nistk233">> -> sect233k1;
		<<"nistb233">> -> sect233r1;
		<<"nistk283">> -> sect283k1;
		<<"nistk409">> -> sect409k1;
		<<"nistb409">> -> sect409r1;
		<<"nistt571">> -> sect571k1;
		_ -> erlang:error({badarg, [P]})
	end.

ec_named_curve_to_domain_parameters(P) ->
	case P of
		secp256r1 -> <<"nistp256">>;
		secp384r1 -> <<"nistp384">>;
		secp521r1 -> <<"nistp521">>;
		sect163k1 -> <<"nistk163">>;
		secp192r1 -> <<"nistp192">>;
		secp224r1 -> <<"nistp224">>;
		sect233k1 -> <<"nistk233">>;
		sect233r1 -> <<"nistb233">>;
		sect283k1 -> <<"nistk283">>;
		sect409k1 -> <<"nistk409">>;
		sect409r1 -> <<"nistb409">>;
		sect571k1 -> <<"nistt571">>;
		_ -> erlang:error({badarg, [P]})
	end.

pkcs7_pad(Bin) ->
	Size = 16 - (byte_size(Bin) rem 16),
	case Size of
		P= 1 -> << Bin/binary, P >>;
		P= 2 -> << Bin/binary, P, P >>;
		P= 3 -> << Bin/binary, P, P, P >>;
		P= 4 -> << Bin/binary, P, P, P, P >>;
		P= 5 -> << Bin/binary, P, P, P, P, P >>;
		P= 6 -> << Bin/binary, P, P, P, P, P, P >>;
		P= 7 -> << Bin/binary, P, P, P, P, P, P, P >>;
		P= 8 -> << Bin/binary, P, P, P, P, P, P, P, P >>;
		P= 9 -> << Bin/binary, P, P, P, P, P, P, P, P, P >>;
		P=10 -> << Bin/binary, P, P, P, P, P, P, P, P, P, P >>;
		P=11 -> << Bin/binary, P, P, P, P, P, P, P, P, P, P, P >>;
		P=12 -> << Bin/binary, P, P, P, P, P, P, P, P, P, P, P, P >>;
		P=13 -> << Bin/binary, P, P, P, P, P, P, P, P, P, P, P, P, P >>;
		P=14 -> << Bin/binary, P, P, P, P, P, P, P, P, P, P, P, P, P, P >>;
		P=15 -> << Bin/binary, P, P, P, P, P, P, P, P, P, P, P, P, P, P, P >>;
		P=16 -> << Bin/binary, P, P, P, P, P, P, P, P, P, P, P, P, P, P, P, P >>
	end.

pkcs7_unpad(Data) ->
	P = binary:last(Data),
	Size = byte_size(Data) - P,
	case Data of
		<< Bin:Size/binary, P >> -> Bin;
		<< Bin:Size/binary, P, P >> -> Bin;
		<< Bin:Size/binary, P, P, P >> -> Bin;
		<< Bin:Size/binary, P, P, P, P >> -> Bin;
		<< Bin:Size/binary, P, P, P, P, P >> -> Bin;
		<< Bin:Size/binary, P, P, P, P, P, P >> -> Bin;
		<< Bin:Size/binary, P, P, P, P, P, P, P >> -> Bin;
		<< Bin:Size/binary, P, P, P, P, P, P, P, P >> -> Bin;
		<< Bin:Size/binary, P, P, P, P, P, P, P, P, P >> -> Bin;
		<< Bin:Size/binary, P, P, P, P, P, P, P, P, P, P >> -> Bin;
		<< Bin:Size/binary, P, P, P, P, P, P, P, P, P, P, P >> -> Bin;
		<< Bin:Size/binary, P, P, P, P, P, P, P, P, P, P, P, P >> -> Bin;
		<< Bin:Size/binary, P, P, P, P, P, P, P, P, P, P, P, P, P >> -> Bin;
		<< Bin:Size/binary, P, P, P, P, P, P, P, P, P, P, P, P, P, P >> -> Bin;
		<< Bin:Size/binary, P, P, P, P, P, P, P, P, P, P, P, P, P, P, P >> -> Bin;
		<< Bin:Size/binary, P, P, P, P, P, P, P, P, P, P, P, P, P, P, P, P >> -> Bin;
		_ -> erlang:error({badarg, Data})
	end.

pem_decode(PEMBinary) when is_binary(PEMBinary) ->
	public_key:pem_decode(PEMBinary).

pem_encode(PEMEntries) when is_list(PEMEntries) ->
	try
		public_key:pem_encode(PEMEntries)
	catch
		Class:Reason:ST ->
			case pem_enc(PEMEntries) of
				{true, PEMBinary} ->
					PEMBinary;
				false ->
					erlang:raise(Class, Reason, ST)
			end
	end.

pem_entry_decode(PEMEntry) ->
	Result =
		try
			public_key:pem_entry_decode(PEMEntry)
		catch
			Class:Reason:ST ->
				case pem_entry_dec(PEMEntry) of
					{true, DecodedPEMEntry} ->
						DecodedPEMEntry;
					false ->
						erlang:raise(Class, Reason, ST)
				end
		end,
	case Result of
		PrivateKeyInfo=#'PrivateKeyInfo'{} ->
			i2k(PrivateKeyInfo);
		SubjectPublicKeyInfo=#'SubjectPublicKeyInfo'{} ->
			i2k(SubjectPublicKeyInfo);
		Other ->
			Other
	end.

pem_entry_decode(PEMEntry, Password0) ->
	Password =
		case Password0 of
			_ when is_binary(Password0) ->
				erlang:binary_to_list(Password0);
			_ ->
				Password0
		end,
	Result =
		try
			public_key:pem_entry_decode(PEMEntry, Password)
		catch
			Class:Reason:ST ->
				case pem_entry_dec(PEMEntry) of
					{true, DecodedPEMEntry} ->
						DecodedPEMEntry;
					false ->
						erlang:raise(Class, Reason, ST)
				end
		end,
	case Result of
		PrivateKeyInfo=#'PrivateKeyInfo'{} ->
			i2k(PrivateKeyInfo);
		SubjectPublicKeyInfo=#'SubjectPublicKeyInfo'{} ->
			i2k(SubjectPublicKeyInfo);
		Other ->
			Other
	end.

pem_entry_encode(ASN1Type, Entity) ->
	try
		public_key:pem_entry_encode(ASN1Type, Entity)
	catch
		Class:Reason:ST ->
			case pem_entry_enc(ASN1Type, Entity) of
				{true, PEMEntry} ->
					PEMEntry;
				false ->
					erlang:raise(Class, Reason, ST)
			end
	end.

pem_entry_encode(ASN1Type, Entity, Password) ->
	try
		public_key:pem_entry_encode(ASN1Type, Entity, Password)
	catch
		Class:Reason:ST ->
			case pem_entry_enc(ASN1Type, Entity, Password) of
				{true, PEMEntry} ->
					PEMEntry;
				false ->
					erlang:raise(Class, Reason, ST)
			end
	end.

ssh_decode(Binary, Type) ->
	Result = public_key:ssh_decode(Binary, Type),
	ssh_dec(Result, Type).

ssh_encode(Entries, Type) ->
	Result = ssh_enc(Entries, Type),
	public_key:ssh_encode(Result, Type).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
pem_enc(Entries) ->
	pem_enc(Entries, []).

%% @private
pem_enc([Entry={'PrivateKeyInfo', _, _} | Entries], Acc) ->
	Encoded =
		try
			public_key:pem_encode([Entry])
		catch
			_:_ ->
				pem_entry_enc(Entry)
		end,
	pem_enc(Entries, [Encoded | Acc]);
pem_enc([Entry | Entries], Acc) ->
	Encoded = public_key:pem_encode([Entry]),
	pem_enc(Entries, [Encoded | Acc]);
pem_enc([], Acc) ->
	{true, erlang:iolist_to_binary(lists:reverse(Acc))}.

%% @private
pem_entry_dec({ASN1Type='PrivateKeyInfo', Der, not_encrypted}) ->
	Entity = der_decode(ASN1Type, Der),
	{true, i2k(Entity)};
pem_entry_dec({ASN1Type='SubjectPublicKeyInfo', Der, not_encrypted}) ->
	Entity = der_decode(ASN1Type, Der),
	{true, i2k(Entity)};
pem_entry_dec(_) ->
	false.

%% @private
pem_entry_enc({'PrivateKeyInfo', Der, EncParams}) ->
	EncodedPEM = public_key:pem_encode([{'ECPrivateKey', Der, EncParams}]),
	erlang:iolist_to_binary(binary:split(EncodedPEM, <<" EC">>, [global, trim_all]));
pem_entry_enc(Entry) ->
	Entry.

%% @private
pem_entry_enc(_, _) ->
	false.

pem_entry_enc(ASN1Type, Entry, {CipherInfo={C, _}, Password}) when C == "AES-128-CBC" ->
	Der = der_encode(ASN1Type, Entry),
	DecryptDer = pem_cipher(Der, CipherInfo, Password),
	{true, {ASN1Type, DecryptDer, CipherInfo}};
pem_entry_enc(_, _, _) ->
	false.

%% @private
pem_cipher(Data, {Cipher = "AES-128-CBC", IV}, Password) ->
	<< Salt:8/binary, _/binary >> = IV,
	{Key, _} = password_to_key_and_iv(Password, Cipher, Salt),
	crypto:block_encrypt(aes_cbc128, Key, IV, pkcs7_pad(Data)).

%% @private
ceiling(Float) -> 
	erlang:round(Float + 0.5).

%% @private
derived_key_length(_, Len) when is_integer(Len) ->
	Len;
derived_key_length(Cipher, _) when (Cipher == "AES-128-CBC") ->
	16.

%% @private
password_to_key_and_iv(Password, Cipher, Salt) ->
	KeyLen = derived_key_length(Cipher, undefined),
	<< Key:KeyLen/binary, _/binary >> =
		pem_encrypt(<<>>, Password, Salt, ceiling(KeyLen div 16), <<>>, md5),
	%% Old PEM encryption does not use standard encryption method
	%% pbdkdf1 and uses then salt as IV
	{Key, Salt}.

%% @private
pem_encrypt(_, _, _, 0, Acc, _) ->
	Acc;
pem_encrypt(Prev, Password, Salt, Count, Acc, Hash) ->
	Result = crypto:hash(Hash, [Prev, Password, Salt]),
	pem_encrypt(Result, Password, Salt, Count-1 , <<Acc/binary, Result/binary>>, Hash).

%% @private
i2k(#'PrivateKeyInfo'{
	privateKeyAlgorithm =
		#'PrivateKeyInfo_privateKeyAlgorithm'{
			algorithm = ?'rsaEncryption'
		},
	privateKey = PrivateKey
}) ->
	der_decode('RSAPrivateKey', PrivateKey);
i2k(#'SubjectPublicKeyInfo'{
	algorithm =
		#'AlgorithmIdentifier'{
			algorithm = ?'rsaEncryption'
		},
	subjectPublicKey = PublicKey
}) ->
	der_decode('RSAPublicKey', PublicKey);
i2k(#'PrivateKeyInfo'{
	privateKeyAlgorithm =
		#'PrivateKeyInfo_privateKeyAlgorithm'{
			algorithm = ?'id-ecPublicKey'
		},
	privateKey = PrivateKey
}) ->
	der_decode('ECPrivateKey', PrivateKey);
i2k(Info) ->
	Info.

%% @private
ssh_dec(List, auth_keys) when is_list(List) ->
	[begin
		case Element of
			{{SignatureAlgorithm, <<
				SignatureAlgorithmSize:32/big-unsigned-integer,
				SignatureAlgorithm:SignatureAlgorithmSize/binary,
				DomainParametersSize:32/big-unsigned-integer,
				DomainParameters:DomainParametersSize/binary,
				OctetsSize:32/big-unsigned-integer,
				Octets:OctetsSize/binary
			>>}, Attributes} ->
				ECPoint = #'ECPoint'{point=Octets},
				CurveId = ec_domain_parameters_to_named_curve(DomainParameters),
				Parameters = pubkey_cert_records:namedCurves(CurveId),
				ECParameters = {namedCurve, Parameters},
				ECPublicKey = {ECPoint, ECParameters},
				{ECPublicKey, Attributes};
			_ ->
				Element
		end
	end || Element <- List];
ssh_dec(Other, _Type) ->
	Other.

%% @private
% ssh_enc(List, auth_keys) when is_list(List) ->
% 	[begin
% 		case Element of
% 			{{#'ECPoint'{point=Octets}, {namedCurve, Parameters}}, Comments} ->
% 				CurveId = pubkey_cert_records:namedCurves(Parameters),
% 				DomainParameters = ec_named_curve_to_domain_parameters(CurveId),
% 				SignatureAlgorithm = << "ecdsa-sha2-", (ec_named_curve_to_domain_parameters(CurveId))/binary >>,
% 				SignatureAlgorithmSize = byte_size(SignatureAlgorithm),
% 				DomainParametersSize = byte_size(DomainParameters),
% 				OctetsSize = byte_size(Octets),
% 				ECPublicKey = {SignatureAlgorithm, <<
% 					SignatureAlgorithmSize:32/big-unsigned-integer,
% 					SignatureAlgorithm:SignatureAlgorithmSize/binary,
% 					DomainParametersSize:32/big-unsigned-integer,
% 					DomainParameters:DomainParametersSize/binary,
% 					OctetsSize:32/big-unsigned-integer,
% 					Octets:OctetsSize/binary
% 				>>},
% 				{ECPublicKey, Comments};
% 			_ ->
% 				Element
% 		end
% 	end || Element <- List];
ssh_enc(Other, _Type) ->
	Other.
