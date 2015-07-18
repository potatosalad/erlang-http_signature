defmodule HTTPSignature do

  def parse_request(method, path, headers, options) do
    :http_signature.parse_request(method, path, headers, options)
  end

  def sign(method, path, headers, options, signer = %HTTPSignature.Signer{}) do
    record = HTTPSignature.Signer.to_record(signer)
    :http_signature.sign(method, path, headers, options, record)
  end

  def sign_request(method, path, headers, options, signer = %HTTPSignature.Signer{}) do
    record = HTTPSignature.Signer.to_record(signer)
    :http_signature.sign_request(method, path, headers, options, record)
  end

  def signature_string(method, path, headers, header_keys) do
    :http_signature.signature_string(method, path, headers, header_keys)
  end

  def verify(method, path, headers, params, verifier = %HTTPSignature.Verifier{}) do
    record = HTTPSignature.Verifier.to_record(verifier)
    :http_signature.verify(method, path, headers, params, record)
  end

  def verify_request(method, path, headers, options, verifier = %HTTPSignature.Verifier{}) do
    record = HTTPSignature.Verifier.to_record(verifier)
    :http_signature.verify_request(method, path, headers, options, record)
  end

end
