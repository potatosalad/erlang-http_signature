defmodule HTTPSignature do
  @moduledoc ~S"""
  [Signing HTTP Messages](https://tools.ietf.org/html/draft-cavage-http-signatures) (or the HTTP Signature Scheme) is still in draft form.
  """

  defdelegate sign(signer, method, path, headers), to: :http_signature
  defdelegate sign(signer, method, path, headers, extra), to: :http_signature
  defdelegate verify(verifier, method, path, headers), to: :http_signature
end
