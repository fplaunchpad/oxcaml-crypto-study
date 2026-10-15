let quarter_round_path = "../vectors/chacha20/quarter_round.txt"
let block_fn_path = "../vectors/chacha20/block_function.txt"
let encryption_path = "../vectors/chacha20/encryption.txt"

module I = Stdlib_upstream_compatible.Int32_u

let test_quarter_round () =
  let open Harness.Testvector_file in
  let test_vecs = parse quarter_round_path in
  let v k = Int32.of_string ("0x" ^ List.assoc k test_vecs) in
  let a, b, c, d =
    Chacha20.Boxed.quarter_round
      (v "a_in", v "b_in", v "c_in", v "d_in")
  in
  Alcotest.(check int32) "a" (v "a_out") a;
  Alcotest.(check int32) "b" (v "b_out") b;
  Alcotest.(check int32) "c" (v "c_out") c;
  Alcotest.(check int32) "d" (v "d_out") d

let test_block_fn () =
  let open Harness.Testvector_file in
  let test_vals = parse block_fn_path in

  let key = str_hex_to_bytes (List.assoc "Key" test_vals) in
  let nonce = str_hex_to_bytes (List.assoc "Nonce" test_vals) in
  let counter = Int32.of_string ("0x" ^ List.assoc "BlockCount" test_vals) in
  let expected_out = format_str (List.assoc "Out" test_vals) in

  let result = Chacha20.Boxed.chacha20_block ~key ~counter ~nonce in
  Alcotest.(check string)
    "block_function" expected_out (bytes_to_str_hex result)

let test_encryption () =
  let open Harness.Testvector_file in
  let test_vals = parse encryption_path in

  let key = str_hex_to_bytes (List.assoc "Key" test_vals) in
  let nonce = str_hex_to_bytes (List.assoc "Nonce" test_vals) in
  let counter =
    Int32.of_string ("0x" ^ List.assoc "InitialCounter" test_vals)
  in
  let plaintext = str_hex_to_bytes (List.assoc "Plaintext" test_vals) in
  let expected_ciphertext = format_str (List.assoc "Ciphertext" test_vals) in

  let actual_ciphertext = Bytes.create (Bytes.length plaintext) in
  Chacha20.Boxed.encrypt ~key ~counter ~nonce ~plaintext
    ~ciphertext:actual_ciphertext;
  Alcotest.(check string)
    "encryption" expected_ciphertext
    (bytes_to_str_hex actual_ciphertext)

let test_libsodium_encryption () =
  let open Harness.Testvector_file in
  let test_vals = parse encryption_path in

  let key = str_hex_to_bytes (List.assoc "Key" test_vals) in
  let nonce = str_hex_to_bytes (List.assoc "Nonce" test_vals) in
  let counter =
    Int32.of_string ("0x" ^ List.assoc "InitialCounter" test_vals)
  in
  let plaintext = str_hex_to_bytes (List.assoc "Plaintext" test_vals) in
  let expected_ciphertext = format_str (List.assoc "Ciphertext" test_vals) in

  let ciphertext =
    Crypto_oracles.Chacha20_stub.ietf_chacha20_encrypt ~key ~counter ~nonce
      ~plaintext
  in
  Alcotest.(check string)
    "encryption" expected_ciphertext
    (bytes_to_str_hex ciphertext)

let test_differential_libsodium_ietf_encryption () =
  QCheck.Test.make ~name:"differential test with libsodium ietf implementation"
    ~count:1000 Harness.Chacha20_qcheck_gen.arbitrary
    (fun (key, nonce, counter, plaintext) ->
      let custom_impl_ciphertext = Bytes.create (Bytes.length plaintext) in
      Chacha20.Boxed.encrypt ~key ~counter ~nonce ~plaintext
        ~ciphertext:custom_impl_ciphertext;

      let libsodium_ciphertext =
        Crypto_oracles.Chacha20_stub.ietf_chacha20_encrypt ~key ~counter ~nonce
          ~plaintext
      in
      Bytes.equal custom_impl_ciphertext libsodium_ciphertext)

(* scalar_unboxed implementation with unboxed types *)

let test_quarter_round_scalar_unboxed () =
  let open Chacha20.Int32_u_array in
  let open Harness.Testvector_file in
  (* tests *)
  let test_vecs = parse quarter_round_path in
  let v k = Int32.of_string ("0x" ^ List.assoc k test_vecs) in
  let v_unboxed k = I.of_string ("0x" ^ List.assoc k test_vecs) in
  let in_arr =
    [| v_unboxed "a_in"; v_unboxed "b_in"; v_unboxed "c_in"; v_unboxed "d_in" |]
  in
  Chacha20.Scalar_unboxed.quarter_round in_arr 0 1 2 3;
  Alcotest.(check int32) "a" (v "a_out") (I.to_int32 in_arr.%(0));
  Alcotest.(check int32) "b" (v "b_out") (I.to_int32 in_arr.%(1));
  Alcotest.(check int32) "c" (v "c_out") (I.to_int32 in_arr.%(2));
  Alcotest.(check int32) "d" (v "d_out") (I.to_int32 in_arr.%(3))

let test_encryption_scalar_unboxed () =
  let open Harness.Testvector_file in
  let test_vals = parse encryption_path in

  let key = str_hex_to_bytes (List.assoc "Key" test_vals) in
  let nonce = str_hex_to_bytes (List.assoc "Nonce" test_vals) in
  let counter =
    Int32.of_string ("0x" ^ List.assoc "InitialCounter" test_vals)
  in
  let plaintext = str_hex_to_bytes (List.assoc "Plaintext" test_vals) in
  let expected_ciphertext = format_str (List.assoc "Ciphertext" test_vals) in
  let ciphertext = Bytes.create (Bytes.length plaintext) in

  Chacha20.Scalar_unboxed.encrypt ~key ~counter ~nonce ~plaintext
    ~ciphertext;

  Alcotest.(check string)
    "encryption" expected_ciphertext
    (bytes_to_str_hex ciphertext)

let test_differential_libsodium_ietf_encryption_scalar_unboxed () =
  QCheck.Test.make
    ~name:"differential test for scalar_unboxed with libsodium ietf implementation"
    ~count:1000 Harness.Chacha20_qcheck_gen.arbitrary
    (fun (key, nonce, counter, plaintext) ->
      let custom_impl_ciphertext = Bytes.create (Bytes.length plaintext) in
      Chacha20.Scalar_unboxed.encrypt ~key ~counter ~nonce ~plaintext
        ~ciphertext:custom_impl_ciphertext;

      let libsodium_ciphertext =
        Crypto_oracles.Chacha20_stub.ietf_chacha20_encrypt ~key ~counter ~nonce
          ~plaintext
      in
      Bytes.equal custom_impl_ciphertext libsodium_ciphertext)

let () =
  Alcotest.run "chacha20"
    [
      ( "rfc8439-vectors",
        [
          Alcotest.test_case "quarter_round" `Quick test_quarter_round;
          Alcotest.test_case "block_function" `Quick test_block_fn;
          Alcotest.test_case "encryption" `Quick test_encryption;
          Alcotest.test_case "quarter_round_scalar_unboxed" `Quick
            test_quarter_round_scalar_unboxed;
          Alcotest.test_case "encryption_scalar_unboxed" `Quick
            test_encryption_scalar_unboxed;
        ] );
      ( "differential-test-with-libsodium-ietf",
        [
          Alcotest.test_case "libsodium encryption" `Slow
            test_libsodium_encryption;
          QCheck_alcotest.to_alcotest
            (test_differential_libsodium_ietf_encryption ());
          QCheck_alcotest.to_alcotest
            (test_differential_libsodium_ietf_encryption_scalar_unboxed ());
        ] );
    ]
