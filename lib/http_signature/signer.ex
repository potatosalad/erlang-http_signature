require Record

defmodule HTTPSignature.Signer do
  record = Record.extract(:http_signature_signer, from_lib: "http_signature/include/http_signature_signer.hrl")
  keys   = :lists.map(&elem(&1, 0), record)
  vals   = :lists.map(&{&1, [], nil}, keys)
  pairs  = :lists.zip(keys, vals)

  defstruct keys
  @type t :: %__MODULE__{}

  @doc """
  Converts a `HTTPSignature.Signer` struct to a `:http_signature_signer` record.
  """
  def to_record(%HTTPSignature.Signer{unquote_splicing(pairs)}) do
    {:http_signature_signer, unquote_splicing(vals)}
  end

  @doc """
  Converts a `:http_signature_signer` record into a `HTTPSignature.Signer`.
  """
  def from_record(http_signature_signer)
  def from_record({:http_signature_signer, unquote_splicing(vals)}) do
    %HTTPSignature.Signer{unquote_splicing(pairs)}
  end

  def from_data(secret_data) do
    case :http_signature_signer.from_data(secret_data) do
      error = {:error, _} ->
        error
      signer ->
        signer |> from_record
    end
  end

  def from_data(secret_pass, secret_data) do
    case :http_signature_signer.from_data(secret_pass, secret_data) do
      error = {:error, _} ->
        error
      signer ->
        signer |> from_record
    end
  end

  def from_file(secret_file) do
    case :http_signature_signer.from_file(secret_file) do
      error = {:error, _} ->
        error
      signer ->
        signer |> from_record
    end
  end

  def from_file(secret_pass, secret_file) do
    case :http_signature_signer.from_file(secret_pass, secret_file) do
      error = {:error, _} ->
        error
      signer ->
        signer |> from_record
    end
  end

  def to_data(signer = %HTTPSignature.Signer{}) do
    :http_signature_signer.to_data(signer |> to_record)
  end

  def to_data(secret_pass, signer = %HTTPSignature.Signer{}) do
    :http_signature_signer.to_data(secret_pass, signer |> to_record)
  end

  def to_file(secret_file, signer = %HTTPSignature.Signer{}) do
    :http_signature_signer.to_file(secret_file, signer |> to_record)
  end

  def to_file(secret_pass, secret_file, signer = %HTTPSignature.Signer{}) do
    :http_signature_signer.to_file(secret_pass, secret_file, signer |> to_record)
  end

  def sign(message, signer = %HTTPSignature.Signer{signer: algorithm}) do
    sign(message, algorithm, signer)
  end

  def sign(message, algorithm, %HTTPSignature.Signer{module: module, secret: secret}) do
    algorithm = :http_signature_algorithm.hash_type(algorithm)
    module.sign(message, algorithm, secret)
  end

  def to_verifier(%HTTPSignature.Signer{module: module, secret: secret}) do
    HTTPSignature.Verifier.from_record(module.to_verifier(secret))
  end

  def verify(message, signature, signer = %HTTPSignature.Signer{signer: algorithm}) do
    verifier = signer |> to_verifier
    HTTPSignature.Verifier.verify(message, algorithm, signature, verifier)
  end
end
