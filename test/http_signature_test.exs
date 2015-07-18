defmodule HTTPSignatureTest do
  use ExUnit.Case

  test "sign_request and verify_request ecdsa" do
    {secret, secret_data} = HTTPSignatureTestHelper.gen_private_key(:ecdsa)
    signer = HTTPSignature.Signer.from_data(secret_data)
    signer = %{signer | key_id: "mykey"}
    assert secret == signer.secret
    verifier = signer |> HTTPSignature.Signer.to_verifier
    {method, path, headers} = HTTPSignature.sign_request("get", "/", %{}, [], signer)
    assert HTTPSignature.verify_request(method, path, headers, [], verifier)
  end

  test "sign_request and verify_request hmac" do
    secret_data = HTTPSignatureTestHelper.gen_hmac
    signer = HTTPSignature.Signer.from_data({:http_signature_hmac, secret_data})
    signer = %{signer | key_id: "mykey"}
    verifier = signer |> HTTPSignature.Signer.to_verifier
    {method, path, headers} = HTTPSignature.sign_request("get", "/", %{}, [], signer)
    assert HTTPSignature.verify_request(method, path, headers, [], verifier)
  end
end
