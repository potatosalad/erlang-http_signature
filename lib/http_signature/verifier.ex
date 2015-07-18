require Record

defmodule HTTPSignature.Verifier do
  record = Record.extract(:http_signature_verifier, from_lib: "http_signature/include/http_signature_verifier.hrl")
  keys   = :lists.map(&elem(&1, 0), record)
  vals   = :lists.map(&{&1, [], nil}, keys)
  pairs  = :lists.zip(keys, vals)

  defstruct keys
  @type t :: %__MODULE__{}

  @doc """
  Converts a `HTTPSignature.Verifier` struct to a `:http_signature_verifier` record.
  """
  def to_record(%HTTPSignature.Verifier{unquote_splicing(pairs)}) do
    {:http_signature_verifier, unquote_splicing(vals)}
  end

  @doc """
  Converts a `:http_signature_verifier` record into a `HTTPSignature.Verifier`.
  """
  def from_record(http_signature_verifier)
  def from_record({:http_signature_verifier, unquote_splicing(vals)}) do
    %HTTPSignature.Verifier{unquote_splicing(pairs)}
  end

  def from_data(public_data) do
    case :http_signature_verifier.from_data(public_data) do
      error = {:error, _} ->
        error
      verifier ->
        verifier |> from_record
    end
  end

  def from_file(public_file) do
    case :http_signature_verifier.from_file(public_file) do
      error = {:error, _} ->
        error
      verifier ->
        verifier |> from_record
    end
  end

  def from_signer(signer = %HTTPSignature.Signer{}) do
    HTTPSignature.Signer.to_verifier(signer)
  end

  def to_data(verifier = %HTTPSignature.Verifier{}) do
    :http_signature_verifier.to_data(verifier |> to_record)
  end

  def to_file(public_file, verifier = %HTTPSignature.Verifier{}) do
    :http_signature_verifier.to_file(public_file, verifier |> to_record)
  end

  def verify(message, algorithm, signature, %HTTPSignature.Verifier{module: module, public: public}) do
    algorithm = :http_signature_algorithm.hash_type(algorithm)
    module.verify(message, algorithm, signature, public)
  end

end
