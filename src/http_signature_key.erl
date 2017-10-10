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
-module(http_signature_key).

-include("http_signature_utils.hrl").
-include_lib("public_key/include/public_key.hrl").

%% Types
-type t(Public, Shared) :: #{
	'__struct__' := ?MODULE,
	attributes := nil | [{term(), term()}],
	id := nil | binary(),
	key := term(),
	module := module(),
	public := Public,
	shared := Shared
}.

-export_type([t/2]).

-type t() :: t(boolean(), boolean()).

-export_type([t/0]).

-type public() :: t(true, false).

-export_type([public/0]).

-type secret() :: t(false, false).

-export_type([secret/0]).

-type shared() :: t(false, true).

-export_type([shared/0]).

%% Elixir API
-export(['__struct__'/0]).
-export(['__struct__'/1]).
%% API
-export([new/0]).
-export([new/1]).
-export([default_sign_algorithm/1]).
-export([fingerprint/1]).
-export([fingerprint/2]).
-export([generate_key/1]).
-export([id/1]).
-export([sign/3]).
-export([verify/4]).
%% Import/Export API
-export([decode_data/1]).
-export([decode_data/2]).
-export([decode_file/1]).
-export([decode_file/2]).
-export([decode_pem/1]).
-export([decode_pem/2]).
-export([decode_ssh/1]).
-export([encode_pem/1]).
-export([encode_pem/2]).
-export([encode_ssh/1]).
-export([from_record/1]).
-export([to_public/1]).

%%%===================================================================
%%% Elixir API functions
%%%===================================================================

-spec '__struct__'() -> t().
'__struct__'() ->
	#{
		'__struct__' => ?MODULE,
		attributes => nil,
		id => nil,
		key => nil,
		module => nil,
		public => nil,
		shared => false
	}.

-spec '__struct__'([{atom(), term()}] | #{ atom() => term() }) -> t().
'__struct__'(List) when is_list(List) ->
	'__struct__'(maps:from_list(List));
'__struct__'(Map) when is_map(Map) ->
	maps:fold(fun maps:update/3, '__struct__'(), Map).

%%%===================================================================
%%% API functions
%%%===================================================================

-spec new() -> t().
new() ->
	new(#{}).

-spec new([{atom(), term()}] | #{ atom() => term() }) -> t().
new(Enumerable) ->
	'__struct__'(Enumerable).

default_sign_algorithm(Key=#{ '__struct__' := ?MODULE, key := Key, public := true }) ->
	?http_signature_throw({cannot_sign_with_public_key, Key}, "Cannot sign with public key", []);
default_sign_algorithm(#{ '__struct__' := ?MODULE, key := Key, module := Module, public := false }) ->
	_ = code:ensure_loaded(Module),
	Module:default_sign_algorithm(Key).

fingerprint(Key=#{ '__struct__' := ?MODULE }) ->
	fingerprint(Key, []).

fingerprint(#{ '__struct__' := ?MODULE, key := Key, module := Module, public := Public, shared := Shared }, DigestTypes)
		when (Public == true andalso Shared == false) orelse (Public == false andalso Shared == true) ->
	_ = code:ensure_loaded(Module),
	case erlang:function_exported(Module, ssh_hostkey_fingerprint, 2) of
		true ->
			Module:ssh_hostkey_fingerprint(Key, DigestTypes);
		false ->
			case DigestTypes of
				[] ->
					FingerprintString = public_key:ssh_hostkey_fingerprint(Key),
					erlang:iolist_to_binary(FingerprintString);
				_ ->
					FingerprintStrings = public_key:ssh_hostkey_fingerprint(DigestTypes, Key),
					[erlang:iolist_to_binary(FingerprintString) || FingerprintString <- FingerprintStrings]
			end
	end;
fingerprint(Key=#{ '__struct__' := ?MODULE, public := false }, DigestTypes) ->
	PublicKey = to_public(Key),
	fingerprint(PublicKey, DigestTypes).

generate_key(#{ '__struct__' := ?MODULE, key := Key, module := Module, public := Public, shared := Shared })
		when (Public == true andalso Shared == false) orelse (Public == false andalso Shared == true) ->
	_ = code:ensure_loaded(Module),
	case erlang:function_exported(Module, generate_key, 1) of
		true ->
			new(#{ key => Module:generate_key(Key), module => Module, public => false, shared => Shared });
		false ->
			generate_key(Key)
	end;
generate_key(Key=#{ '__struct__' := ?MODULE, public := false }) ->
	PublicKey = to_public(Key),
	generate_key(PublicKey);
% DSA
generate_key(DSAPrivateKey=#'DSAPrivateKey'{}) ->
	#{ key := DSAPublicKey } = to_public(from_record(DSAPrivateKey)),
	generate_key(DSAPublicKey);
generate_key({_, DSAParams=#'Dss-Parms'{}}) ->
	generate_key({dsa, DSAParams});
generate_key({dsa, Params}) ->
	Key = #'DSAPrivateKey'{} = http_signature_dsa:generate_key(Params),
	from_record(Key);
% EC
generate_key(#'ECPrivateKey'{ parameters = P }) ->
	generate_key({ecdsa, P});
generate_key({#'ECPoint'{}, P}) ->
	generate_key({ecdsa, P});
generate_key(P = #'ECParameters'{}) ->
	generate_key({ecdsa, P});
generate_key({ecdsa, Params}) ->
	Key = #'ECPrivateKey'{} = http_signature_ecdsa:generate_key(Params),
	from_record(Key);
% HMAC
generate_key({hmac, Params}) ->
	Key = {hmac, << _/binary >>} = http_signature_hmac:generate_key(Params),
	from_record(Key);
% RSA
generate_key(RSAPrivateKey = #'RSAPrivateKey'{}) ->
	generate_key({rsa, RSAPrivateKey});
generate_key(RSAPublicKey = #'RSAPublicKey'{}) ->
	generate_key({rsa, RSAPublicKey});
generate_key({rsa, Params}) ->
	Key = #'RSAPrivateKey'{} = http_signature_rsa:generate_key(Params),
	from_record(Key);
generate_key({rsa, ModulusSize, ExponentSize})
		when is_integer(ModulusSize)
		andalso is_integer(ExponentSize) ->
	Key = #'RSAPrivateKey'{} = http_signature_rsa:generate_key({ModulusSize, ExponentSize}),
	from_record(Key).

id(#{ '__struct__' := ?MODULE, id := ID }) when is_binary(ID) ->
	ID;
id(Struct=#{ '__struct__' := ?MODULE, id := nil, key := Key, module := Module }) ->
	_ = code:ensure_loaded(Module),
	case erlang:function_exported(Module, id, 1) of
		true ->
			Module:id(Key);
		false ->
			fingerprint(Struct)
	end.

sign(Key=#{ '__struct__' := ?MODULE, public := true }, _Algorithm, _Message) ->
	?http_signature_throw({cannot_sign_with_public_key, Key}, "Cannot sign with public key", []);
sign(#{ '__struct__' := ?MODULE, key := Key, module := Module, public := false }, Algorithm, Message) ->
	_ = code:ensure_loaded(Module),
	Module:sign(Key, Algorithm, Message).

verify(#{ '__struct__' := ?MODULE, key := Key, module := Module, public := Public, shared := Shared }, Algorithm, Signature, Message)
		when (Public == true andalso Shared == false) orelse (Public == false andalso Shared == true) ->
	_ = code:ensure_loaded(Module),
	Module:verify(Key, Algorithm, Signature, Message);
verify(Key=#{ '__struct__' := ?MODULE, public := false }, Algorithm, Signature, Message) ->
	PublicKey = to_public(Key),
	verify(PublicKey, Algorithm, Signature, Message).

%%%===================================================================
%%% Import/Export API functions
%%%===================================================================

decode_data(Data) ->
	try
		decode_pem(Data)
	catch
		Class:Reason ->
			ST = erlang:get_stacktrace(),
			try
				decode_ssh(Data)
			catch
				_:_ ->
					erlang:raise(Class, Reason, ST)
			end
	end.

decode_data(Data, Password) ->
	decode_pem(Data, Password).

decode_file(File) ->
	case file:read_file(File) of
		{ok, Data} ->
			decode_data(Data);
		{error, Reason} ->
			erlang:error(Reason)
	end.

decode_file(File, Password) ->
	case file:read_file(File) of
		{ok, Data} ->
			decode_data(Data, Password);
		{error, Reason} ->
			erlang:error(Reason)
	end.

decode_pem(PEMBinary) when is_binary(PEMBinary) ->
	[PEMEntryEncoded] = http_signature_public_key:pem_decode(PEMBinary),
	from_record(http_signature_public_key:pem_entry_decode(PEMEntryEncoded)).

decode_pem(PEMBinary, Password) when is_binary(PEMBinary) ->
	[PEMEntryEncoded] = http_signature_public_key:pem_decode(PEMBinary),
	from_record(http_signature_public_key:pem_entry_decode(PEMEntryEncoded, Password)).

decode_ssh(Data) ->
	case http_signature_public_key:ssh_decode(Data, auth_keys) of
		[{DSAPublicKey={_, #'Dss-Parms'{}}, Attributes} | _] ->
			maps:update(attributes, Attributes, from_record(DSAPublicKey));
		[{RSAPublicKey=#'RSAPublicKey'{}, Attributes} | _] ->
			maps:update(attributes, Attributes, from_record(RSAPublicKey));
		[{ECPublicKey={#'ECPoint'{}, _}, Attributes} | _] ->
			maps:update(attributes, Attributes, from_record(ECPublicKey));
		_ ->
			erlang:error({badarg, [Data]})
	end.

encode_pem(#{ '__struct__' := ?MODULE, key := Key, module := Module }) ->
	_ = code:ensure_loaded(Module),
	Module:encode_pem(Key).

encode_pem(#{ '__struct__' := ?MODULE, key := Key, module := Module }, Password) ->
	_ = code:ensure_loaded(Module),
	Module:encode_pem(Key, Password).

encode_ssh(#{ '__struct__' := ?MODULE, attributes := Attributes0, key := Key, module := Module, public := Public, shared := Shared })
		when (Public == true andalso Shared == false) orelse (Public == false andalso Shared == true) ->
	_ = code:ensure_loaded(Module),
	case erlang:function_exported(Module, encode_ssh, 2) of
		true ->
			Module:encode_ssh(Key, Attributes0);
		false ->
			Attributes1 =
				case Attributes0 of
					nil ->
						[];
					_ ->
						Attributes0
				end,
			Entries = [{Key, Attributes1}],
			http_signature_public_key:ssh_encode(Entries, auth_keys)
	end;
encode_ssh(Key=#{ '__struct__' := ?MODULE, public := false }) ->
	PublicKey = to_public(Key),
	encode_ssh(PublicKey).

from_record(Key=#'DSAPrivateKey'{}) ->
	new(#{ key => Key, module => http_signature_dsa, public => false });
from_record(Key={_, #'Dss-Parms'{}}) ->
	new(#{ key => Key, module => http_signature_dsa, public => true });
from_record(Key=#'ECPrivateKey'{}) ->
	new(#{ key => Key, module => http_signature_ecdsa, public => false });
from_record(Key={#'ECPoint'{}, _}) ->
	new(#{ key => Key, module => http_signature_ecdsa, public => true });
from_record(Key=#'RSAPrivateKey'{}) ->
	new(#{ key => Key, module => http_signature_rsa, public => false });
from_record(Key=#'RSAPublicKey'{}) ->
	new(#{ key => Key, module => http_signature_rsa, public => true });
from_record(#'PrivateKeyInfo'{privateKeyAlgorithm=#'PrivateKeyInfo_privateKeyAlgorithm'{algorithm=?'id-dsa'}, privateKey=PrivateKey}) ->
	from_record(http_signature_public_key:der_decode('DSAPrivateKey', PrivateKey));
from_record(#'PrivateKeyInfo'{privateKeyAlgorithm=#'PrivateKeyInfo_privateKeyAlgorithm'{algorithm=?'id-ecPublicKey'}, privateKey=PrivateKey}) ->
	from_record(http_signature_public_key:der_decode('ECPrivateKey', PrivateKey));
from_record(#'PrivateKeyInfo'{privateKeyAlgorithm=#'PrivateKeyInfo_privateKeyAlgorithm'{algorithm=?rsaEncryption}, privateKey=PrivateKey}) ->
	from_record(http_signature_public_key:der_decode('RSAPrivateKey', PrivateKey));
from_record({hmac, Key}) when is_binary(Key) ->
	new(#{ key => {hmac, Key}, module => http_signature_hmac, public => false, shared => true });
from_record(BadArg) ->
	erlang:error({badarg, [BadArg]}).

to_public(Key = #{ '__struct__' := ?MODULE, public := true }) ->
	Key;
to_public(Key = #{ '__struct__' := ?MODULE, public := false, shared := true }) ->
	erlang:error({badarg, [Key]});
to_public(#{ '__struct__' := ?MODULE, key := Key, module := Module, public := false, shared := false }) ->
	_ = code:ensure_loaded(Module),
	case erlang:function_exported(Module, to_public, 1) of
		true ->
			new(#{ key => Module:to_public(Key), module => Module, public => true });
		false ->
			case Key of
				#'DSAPrivateKey'{y=Y, p=P, q=Q, g=G} ->
					DSAPublicKey = {Y, #'Dss-Parms'{p=P, q=Q, g=G}},
					new(#{ key => DSAPublicKey, module => Module, public => true });
				DSAPublicKey={_, #'Dss-Parms'{}} ->
					new(#{ key => DSAPublicKey, module => Module, public => true });
				#'ECPrivateKey'{parameters=ECParameters, publicKey=Octets0} ->
					Octets = case Octets0 of
						{_, Octets1} ->
							Octets1;
						_ ->
							Octets0
					end,
					ECPoint = #'ECPoint'{point=Octets},
					ECPublicKey = {ECPoint, ECParameters},
					new(#{ key => ECPublicKey, module => Module, public => true });
				ECPublicKey={#'ECPoint'{}, _} ->
					new(#{ key => ECPublicKey, module => Module, public => true });
				#'RSAPrivateKey'{modulus=Modulus, publicExponent=PublicExponent} ->
					RSAPublicKey = #'RSAPublicKey'{modulus=Modulus, publicExponent=PublicExponent},
					new(#{ key => RSAPublicKey, module => Module, public => true });
				RSAPublicKey=#'RSAPublicKey'{} ->
					new(#{ key => RSAPublicKey, module => Module, public => true })
			end
	end.

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------
