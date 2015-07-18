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

-include("http_signature.hrl").

%% API
-export([parse_request/4]).
-export([sign/5]).
-export([sign_request/5]).
-export([signature_string/4]).
-export([verify/5]).
-export([verify_request/5]).

%% Utility API
-export([constant_time_compare/2]).

%% Types
-type algorithm() ::
	{http_signature_algorithm:key_type(),
		http_signature_algorithm:hash_type()}.
-type key_id() :: iodata().
-type public() ::
	http_signature_hmac:public() |
	http_signature_public_key:public().
-type secret() ::
	http_signature_hmac:secret() |
	http_signature_private_key:secret().

-export_type([algorithm/0]).
-export_type([key_id/0]).
-export_type([public/0]).
-export_type([secret/0]).

%%====================================================================
%% API functions
%%====================================================================

parse_request(Method0, Path0, Headers0 = #{}, Options) ->
	Method1 = lowercase_binary(Method0),
	Path1 = lowercase_binary(Path0),
	Headers1 = lowercase_headers(Headers0),
	case Headers1 of
		#{ <<"authorization">> := Authorization } ->
			case parse_auth(Authorization) of
				{<<"signature">>, AuthParams} ->
					parse_request_params(Method1, Path1, Headers1, AuthParams, Options);
				{Scheme, _} ->
					{error, {unsupported_authorization_scheme, Scheme}}
			end;
		_ ->
			{error, missing_authorization_header}
	end.

sign(Method0, Path0, Headers0 = #{}, Options, Signer) ->
	Algorithm = proplists:get_value(algorithm, Options, http_signature_signer:algorithm(Signer)),
	OptionHeaderKeys = proplists:get_value(headers, Options, []),
	KeyId = proplists:get_value(key_id, Options, http_signature_signer:key_id(Signer)),
	Method1 = lowercase_binary(Method0),
	Path1 = lowercase_binary(Path0),
	Headers1 = lowercase_headers(Headers0),
	DateHeaderKey = case maps:is_key(<<"x-date">>, Headers1) of
		false ->
			case lists:member(<<"x-date">>, OptionHeaderKeys) of
				false ->
					<<"date">>;
				true ->
					<<"x-date">>
			end;
		true ->
			<<"x-date">>
	end,
	DefaultHeaderKeys = [DateHeaderKey],
	HeaderKeys = case OptionHeaderKeys of
		[] ->
			DefaultHeaderKeys;
		_ ->
			OptionHeaderKeys
	end,
	Headers2 = case maps:is_key(DateHeaderKey, Headers1) of
		false ->
			Headers1#{ DateHeaderKey => http_signature_date:rfc1123() };
		true ->
			Headers1
	end,
	SignatureString = signature_string(Method1, Path1, Headers2, HeaderKeys),
	Signature = base64:encode(http_signature_signer:sign(SignatureString, Algorithm, Signer)),
	{Method1, Path1, Headers2, #{
		keyId => KeyId,
		algorithm => Algorithm,
		headers => HeaderKeys,
		signature => Signature
	}}.

sign_request(Method0, Path0, Headers0 = #{}, Options, Signer) ->
	{Method1, Path1, Headers1, #{
		keyId := KeyId,
		algorithm := Algorithm,
		headers := HeaderKeys,
		signature := Signature
	}} = sign(Method0, Path0, Headers0, Options, Signer),
	Headers2 = Headers1#{
		<<"authorization">> => <<
			"Signature keyId=\"",
			KeyId/binary,
			"\",algorithm=\"",
			(http_signature_algorithm:to_binary(Algorithm))/binary,
			(case HeaderKeys of
				[<<"date">>] ->
					<<>>;
				_ ->
					<< $\s, HeadersList/binary >> = << << $\s, HeaderKey/binary >> || HeaderKey <- HeaderKeys >>,
					<< "\",headers=\"", HeadersList/binary >>
			end)/binary,
			"\",signature=\"",
			Signature/binary,
			"\""
		>>
	},
	{Method1, Path1, Headers2}.

signature_string(Method, Path, Headers = #{}, HeaderKeys = [_ | _])
		when is_binary(Method)
		andalso is_binary(Path) ->
	<< $\n, SignatureString/binary >> = <<
		<<
			(case HeaderKey of
				<<"(request-target)">> ->
					<< $\n, HeaderKey/binary, $:, $\s, Method/binary, $\s, Path/binary >>;
				_ ->
					<< $\n, HeaderKey/binary, $:, $\s, (maps:get(HeaderKey, Headers))/binary >>
			end)/binary
		>> || HeaderKey <- HeaderKeys
	>>,
	SignatureString;
signature_string(Method, Path, Headers = #{}, HeaderKeys = [_ | _]) ->
	signature_string(lowercase_binary(Method), lowercase_binary(Path), Headers, HeaderKeys);
signature_string(Method, Path, Headers = #{ <<"x-date">> := _ }, []) ->
	signature_string(Method, Path, Headers, [<<"x-date">>]);
signature_string(Method, Path, Headers = #{ <<"date">> := _ }, []) ->
	signature_string(Method, Path, Headers, [<<"date">>]).

verify(Method, Path, Headers, #{
		algorithm := Algorithm,
		headers := HeaderKeys,
		signature := EncodedSignature }, Verifier) ->
	SignatureString = signature_string(Method, Path, Headers, HeaderKeys),
	DecodedSignature = base64:decode(EncodedSignature),
	http_signature_verifier:verify(SignatureString, Algorithm, DecodedSignature, Verifier).

verify_request(Method0, Path0, Headers0, Options, Verifier) ->
	case parse_request(Method0, Path0, Headers0, Options) of
		{ok, {Method1, Path1, Headers1, Params}} ->
			verify(Method1, Path1, Headers1, Params, Verifier);
		ParseRequestError ->
			ParseRequestError
	end.

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

%% @private
lowercase_binary(Atom) when is_atom(Atom) ->
	lowercase_binary(atom_to_binary(Atom, unicode));
lowercase_binary(Binary) when is_binary(Binary) ->
	?INLINE_LOWERCASE_BC(Binary);
lowercase_binary(List) when is_list(List) ->
	lowercase_binary(unicode:characters_to_binary(List)).

%% @private
lowercase_headers(Headers) ->
	Folder = fun
		Folder(Key, Val, Acc) when is_binary(Key) ->
			Acc#{ ?INLINE_LOWERCASE_BC(Key) => Val };
		Folder(Key, Val, Acc) when is_atom(Key) ->
			Folder(atom_to_binary(Key, unicode), Val, Acc);
		Folder(Key, Val, Acc) when is_list(Key) ->
			Folder(unicode:characters_to_binary(Key), Val, Acc)
	end,
	maps:fold(Folder, #{}, Headers).

%% @private
parse_request_params(Method, Path, Headers, Params0 = #{
		<<"keyid">> := KeyId}, Options) ->
	Params1 = maps:remove(<<"keyid">>, Params0),
	Params2 = Params1#{ keyId => KeyId },
	parse_request_params(Method, Path, Headers, Params2, Options);
parse_request_params(Method, Path, Headers, Params0 = #{
		<<"algorithm">> := AlgorithmString}, Options) ->
	Algorithm = http_signature_algorithm:normalize(AlgorithmString),
	OptionAlgorithms = [begin
		http_signature_algorithm:normalize(A)
	end || A <- proplists:get_value(algorithms, Options, http_signature_algorithm:supported())],
	case lists:member(Algorithm, OptionAlgorithms) of
		true ->
			Params1 = maps:remove(<<"algorithm">>, Params0),
			Params2 = Params1#{ algorithm => Algorithm },
			parse_request_params(Method, Path, Headers, Params2, Options);
		false ->
			{error, {unsupported_algorithm, AlgorithmString}}
	end;
parse_request_params(Method, Path, Headers, Params0 = #{
		<<"headers">> := HeaderKeysString}, Options) ->
	HeaderKeys = parse_auth_headers(HeaderKeysString),
	OptionHeaderKeys = proplists:get_value(headers, Options, []),
	case OptionHeaderKeys -- HeaderKeys of
		[] ->
			Params1 = maps:remove(<<"headers">>, Params0),
			Params2 = Params1#{ headers => HeaderKeys },
			parse_request_params(Method, Path, Headers, Params2, Options);
		NonSignedHeaderKeys ->
			{error, {non_signed_headers, NonSignedHeaderKeys}}
	end;
parse_request_params(Method, Path, Headers, Params0 = #{
		<<"signature">> := Signature}, Options) ->
	Params1 = maps:remove(<<"signature">>, Params0),
	Params2 = Params1#{ signature => Signature },
	parse_request_params(Method, Path, Headers, Params2, Options);
parse_request_params(Method, Path, Headers, Params = #{
		keyId := _KeyId,
		algorithm := _Algorithm,
		headers := SignedHeaderKeys,
		signature := _Signature}, Options) ->
	HeaderKeys = maps:keys(Headers),
	case (SignedHeaderKeys -- [<<"(request-target)">>]) -- HeaderKeys of
		[] ->
			parse_request_date(Method, Path, Headers, Params, Options);
		MissingHeaderKeys ->
			{error, {missing_signed_headers, MissingHeaderKeys}}
	end;
parse_request_params(Method, Path, Headers, Params0 = #{
		keyId := _, algorithm := _, signature := _}, Options) ->
	OptionHeaderKeys = proplists:get_value(headers, Options, []),
	DateHeaderKey = case maps:is_key(<<"x-date">>, Headers) of
		false ->
			case lists:member(<<"x-date">>, OptionHeaderKeys) of
				false ->
					<<"date">>;
				true ->
					<<"x-date">>
			end;
		true ->
			<<"x-date">>
	end,
	DefaultHeaderKeys = [DateHeaderKey],
	HeaderKeys = case OptionHeaderKeys of
		[] ->
			DefaultHeaderKeys;
		_ ->
			OptionHeaderKeys
	end,
	Params1 = Params0#{ headers => HeaderKeys },
	parse_request_params(Method, Path, Headers, Params1, Options);
parse_request_params(_Method, _Path, _Headers, Params, _Options) ->
	ParamKeys = maps:keys(Params),
	RequiredKeys = [keyId, algorithm, signature],
	MissingKeys = RequiredKeys - ParamKeys,
	{error, {missing_required_params, MissingKeys}}.

%% @private
parse_request_date(Method, Path, Headers, Params = #{
		headers := SignedHeaderKeys }, Options) ->
	AtLeastOneOfKeys = [<<"x-date">>, <<"date">>],
	case AtLeastOneOfKeys -- SignedHeaderKeys of
		[] ->
			parse_request_date(Method, Path, Headers, Params, <<"x-date">>, Options);
		[<<"x-date">>] ->
			parse_request_date(Method, Path, Headers, Params, <<"date">>, Options);
		[<<"date">>] ->
			parse_request_date(Method, Path, Headers, Params, <<"x-date">>, Options);
		MissingAtLeastOneOfKeys ->
			{error, {missing_at_least_one_of_headers, MissingAtLeastOneOfKeys}}
	end.

%% @private
parse_request_date(Method, Path, Headers, Params, DateHeader, Options) ->
	DateString = maps:get(DateHeader, Headers),
	ClockSkew = proplists:get_value(clock_skew, Options, 300),
	Now = calendar:universal_time(),
	Date = http_signature_date:parse_date(DateString),
	NowSeconds = calendar:datetime_to_gregorian_seconds(Now),
	DateSeconds = calendar:datetime_to_gregorian_seconds(Date),
	case abs(NowSeconds - DateSeconds) of
		Skew when Skew > ClockSkew ->
			{error, {clock_skew, Skew, ClockSkew}};
		_ ->
			{ok, {Method, Path, Headers, Params}}
	end.

%% @private
parse_auth_headers(Headers) ->
	[Header || Header <- binary:split(Headers, << $\s >>, [global, trim]), Header =/= <<>>].

%% @private
parse_auth(Authorization) ->
	parse_auth_scheme(Authorization, <<>>).

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
