let ietf_chacha20_encrypt ~(key:bytes) ~(counter:int32) ~(nonce:bytes)  ~(plaintext:bytes): (bytes) =
  let msg_len = Bytes.length plaintext in
  let ciphertext = Bytes.create msg_len in
  let open Ctypes in
  let c_plain = Ctypes.ocaml_bytes_start plaintext in
  let c_key = Ctypes.ocaml_bytes_start key in
  let c_nonce = Ctypes.ocaml_bytes_start nonce in
  let c_cipher = Ctypes.ocaml_bytes_start ciphertext in
  let result = C.Functions.crypto_stream_chacha20_ietf_xor_ic c_cipher c_plain (Unsigned.ULLong.of_int msg_len) c_nonce (Unsigned.UInt32.of_int32 counter) c_key in
  if result <> 0 then failwith "libsodium 'crypto_stream_chacha20_ietf_xor_ic' returned a non-zero result"
  else ciphertext
