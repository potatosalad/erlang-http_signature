defmodule HTTPSignature.SignerTest do
  use ExUnit.Case

  test "roundtrip from_data/1 and to_data/1" do
    {secret, secret_data} = HTTPSignatureTestHelper.gen_private_key(:ecdsa)
    signer = HTTPSignature.Signer.from_data(secret_data)
    assert secret == signer.secret
    {_, secret_data2} = HTTPSignature.Signer.to_data(signer)
    assert secret_data == secret_data2
  end

  test "roundtrip from_data/2 and to_data/2 ecdsa" do
    {secret, secret_data} = HTTPSignatureTestHelper.gen_private_key(:ecdsa)
    signer = HTTPSignature.Signer.from_data(secret_data)
    {_, secret_data_encrypted} = HTTPSignature.Signer.to_data("password", signer)
    assert secret_data != secret_data_encrypted
    decrypted_signer = HTTPSignature.Signer.from_data("password", secret_data_encrypted)
    assert signer == decrypted_signer
    assert secret == decrypted_signer.secret
    {_, secret_data2} = HTTPSignature.Signer.to_data(decrypted_signer)
    assert secret_data == secret_data2
  end

  test "roundtrip from_data/2 and to_data/2 hmac" do
    secret_data = HTTPSignatureTestHelper.gen_hmac
    signer = HTTPSignature.Signer.from_data({:http_signature_hmac, secret_data})
    {_, secret_data_encrypted} = HTTPSignature.Signer.to_data("password", signer)
    assert secret_data != secret_data_encrypted
    decrypted_signer = HTTPSignature.Signer.from_data("password", {:http_signature_hmac, secret_data_encrypted})
    assert signer == decrypted_signer
    assert {:http_signature_hmac, secret_data} == decrypted_signer.secret
    {_, secret_data2} = HTTPSignature.Signer.to_data(decrypted_signer)
    assert secret_data == secret_data2
  end

  test "sign and verify ecdsa" do
    {secret, secret_data} = HTTPSignatureTestHelper.gen_private_key(:ecdsa)
    signer = HTTPSignature.Signer.from_data(secret_data)
    assert secret == signer.secret
    message = "my message"
    signature = HTTPSignature.Signer.sign(message, signer)
    assert message != signature
    assert HTTPSignature.Signer.verify(message, signature, signer)
  end

  test "sign and verify hmac" do
    secret_data = HTTPSignatureTestHelper.gen_hmac
    signer = HTTPSignature.Signer.from_data({:http_signature_hmac, secret_data})
    message = "my message"
    signature = HTTPSignature.Signer.sign(message, signer)
    assert message != signature
    assert HTTPSignature.Signer.verify(message, signature, signer)
  end
end
