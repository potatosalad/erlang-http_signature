defmodule HTTPSignatureTest do
  use ExUnit.Case, async: true
  use Quixir

  doctest HTTPSignature

  test "sign and verify" do
    ptest [key_params: gen_key_params(), method: gen_method(), path_components: gen_path_components(), query_components: gen_query_components(), headers: gen_headers(), extra: gen_headers()] do
      path = "/" <> Enum.join(path_components, "/")
      query = URI.encode_query(query_components)
      query =
        if byte_size(query) == 0 do
          nil
        else
          query
        end
      uri = %URI{ path: path, query: query }
      path = URI.to_string(uri)
      {keygen_params, algorithm} = key_params
      key = :http_signature_key.generate_key(keygen_params)
      signer = :http_signature_signer.new(key, algorithm)
      verifier = :http_signature_verifier.new(key, [algorithm])
      request = HTTPSignature.sign(signer, method, path, headers)
      assert HTTPSignature.verify(verifier, method, path, request.headers)
      headers_parameters = ["(request-target)", "date" | (Map.keys(request.headers) -- ["authorization"])]
      signer = :http_signature_signer.new(key, algorithm, headers_parameters)
      verifier = :http_signature_verifier.new(key, [algorithm])
      request = HTTPSignature.sign(signer, method, path, headers, extra)
      assert HTTPSignature.verify(verifier, method, path, request.headers)
    end
  end

  @doc false
  def gen_headers(options \\ []) do
    map(of: [{gen_header_key(), gen_path_component()}] ++ options)
  end

  @doc false
  def gen_header_key(options \\ []) do
    choose(from: [
      string([chars: :digits, min: 1] ++ options),
      string([chars: :lower, min: 1] ++ options),
      string([chars: :upper, min: 1] ++ options)
    ])
  end

  @doc false
  def gen_key_params() do
    choose(from: [
      gen_key_params_dsa(),
      gen_key_params_ecdsa(),
      gen_key_params_hmac(),
      gen_key_params_rsa()
    ])
  end

  @doc false
  def gen_key_params_dsa() do
    tuple(like: {value({:dsa, 1024}), choose(from: [
      value(<<"dsa-sha1">>)
    ])})
  end

  @doc false
  def gen_key_params_ecdsa() do
    tuple(like: {tuple(like: {value(:ecdsa), choose(from: [
      value(<<"nistp256">>),
      value(<<"nistp384">>),
      value(<<"nistp521">>)
    ])}), choose(from: [
      value(<<"ecdsa-sha1">>),
      value(<<"ecdsa-sha224">>),
      value(<<"ecdsa-sha256">>),
      value(<<"ecdsa-sha384">>),
      value(<<"ecdsa-sha512">>)
    ])})
  end

  @doc false
  def gen_key_params_hmac() do
    tuple(like: {tuple(like: {value(:hmac), int(min: 1, max: 128)}), choose(from: [
      value(<<"hmac-sha1">>),
      value(<<"hmac-sha224">>),
      value(<<"hmac-sha256">>),
      value(<<"hmac-sha384">>),
      value(<<"hmac-sha512">>)
    ])})
  end

  @doc false
  def gen_key_params_rsa() do
    tuple(like: {tuple(like: {value(:rsa), choose(from: [
      value(768),
      value(1024)
    ])}), choose(from: [
      value(<<"rsa-sha1">>),
      value(<<"rsa-sha224">>),
      value(<<"rsa-sha256">>),
      value(<<"rsa-sha384">>),
      value(<<"rsa-sha512">>)
    ])})
  end

  @doc false
  def gen_method() do
    choose(from: [
      value(:get),
      value(:head),
      value(:post),
      value(:put),
      value(:delete),
      value(:connect),
      value(:options),
      value(:trace),
      value(:patch),
      value(:GET),
      value(:HEAD),
      value(:POST),
      value(:PUT),
      value(:DELETE),
      value(:CONNECT),
      value(:OPTIONS),
      value(:TRACE),
      value(:PATCH),
      value("get"),
      value("head"),
      value("post"),
      value("put"),
      value("delete"),
      value("connect"),
      value("options"),
      value("trace"),
      value("patch"),
      value("GET"),
      value("HEAD"),
      value("POST"),
      value("PUT"),
      value("DELETE"),
      value("CONNECT"),
      value("OPTIONS"),
      value("TRACE"),
      value("PATCH")
    ])
  end

  def gen_path_component() do
    choose(from: [
      string(chars: :digits),
      string(chars: :lower),
      string(chars: :upper)
    ])
  end

  @doc false
  def gen_path_components(options \\ []) do
    list([of: gen_path_component()] ++ options)
  end

  @doc false
  def gen_query_components(options \\ []) do
    map(of: [{gen_path_component(), gen_path_component()}] ++ options)
  end
end
