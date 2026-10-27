let quarter_round_path = "../vectors/chacha20/quarter_round.txt"
let block_fn_path = "../vectors/chacha20/block_function.txt"
let encryption_path = "../vectors/chacha20/encryption.txt"

let test_quarter_round () =
  let open Harness.Testvector_file in
  let test_vecs = parse quarter_round_path in
  let v k = Int32.of_string ("0x" ^ List.assoc k test_vecs) in
  let a, b, c, d =
    Chacha20.Vanilla.quarter_round (v "a_in", v "b_in", v "c_in", v "d_in")
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

  let result = Chacha20.Vanilla.chacha20_block ~key ~counter ~nonce in
  Alcotest.(check string)
    "block_function" expected_out (bytes_to_str_hex result)

let test_rfc_encryption encrypt_fn () =
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

  encrypt_fn ~key ~counter ~nonce ~plaintext ~ciphertext;

  Alcotest.(check string)
    "rfc-encryption" expected_ciphertext
    (bytes_to_str_hex ciphertext)

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

let test_differential_libsodium_ietf_encryption name encrypt_fn =
  QCheck.Test.make ~name ~count:1000 Harness.Chacha20_qcheck_gen.arbitrary
    (fun (key, nonce, counter, plaintext) ->
      let custom_impl_ciphertext = Bytes.create (Bytes.length plaintext) in
      encrypt_fn ~key ~counter ~nonce ~plaintext
        ~ciphertext:custom_impl_ciphertext;

      let libsodium_ciphertext =
        Crypto_oracles.Chacha20_stub.ietf_chacha20_encrypt ~key ~counter ~nonce
          ~plaintext
      in
      Bytes.equal custom_impl_ciphertext libsodium_ciphertext)

let test_quarter_round_scalar_unboxed () =
  let open Chacha20.Int32_u_array in
  let open Harness.Testvector_file in
  let open Stdlib_upstream_compatible.Int32_u in
  (* tests *)
  let test_vecs = parse quarter_round_path in
  let v k = Int32.of_string ("0x" ^ List.assoc k test_vecs) in
  let v_unboxed k = of_string ("0x" ^ List.assoc k test_vecs) in
  let in_arr =
    [| v_unboxed "a_in"; v_unboxed "b_in"; v_unboxed "c_in"; v_unboxed "d_in" |]
  in
  Chacha20.Scalar_unboxed.quarter_round in_arr 0 1 2 3;
  Alcotest.(check int32) "a" (v "a_out") (to_int32 in_arr.%(0));
  Alcotest.(check int32) "b" (v "b_out") (to_int32 in_arr.%(1));
  Alcotest.(check int32) "c" (v "c_out") (to_int32 in_arr.%(2));
  Alcotest.(check int32) "d" (v "d_out") (to_int32 in_arr.%(3))

(* Testing tail lengths.
   The ciphertext buffer has [guard] extra bytes of 0xaa after the message, to catch a write past the end.
   Each test also checks that the plaintext is not changed. *)

let tail_lengths = [ 0; 1; 3; 4; 63; 64; 65; 127 ]

let test_tail_length encrypt len () =
  let open Harness.Testvector_file in
  let key = Bytes.init 32 (fun i -> Char.chr i) in
  let nonce = Bytes.init 12 (fun i -> Char.chr (0xa0 + i)) in
  let counter = 1l in
  let plaintext =
    Bytes.init len (fun i -> Char.chr (((i * 7) + 3) land 0xff))
  in
  let guard = 8 in
  let ciphertext = Bytes.make (len + guard) '\xaa' in
  let plaintext_before = Bytes.copy plaintext in

  encrypt ~key ~counter ~nonce ~plaintext ~ciphertext;
  let expected =
    Crypto_oracles.Chacha20_stub.ietf_chacha20_encrypt ~key ~counter ~nonce
      ~plaintext
  in

  Alcotest.(check string)
    (Printf.sprintf "ciphertext, plaintext length = %d" len)
    (bytes_to_str_hex expected)
    (bytes_to_str_hex (Bytes.sub ciphertext 0 len));

  Alcotest.(check string)
    (Printf.sprintf
       "bytes after the message (> plaintext length), plaintext length = %d" len)
    (String.make guard '\xaa')
    (Bytes.sub_string ciphertext len guard);

  Alcotest.(check string)
    (Printf.sprintf "plaintext unchanged, length = %d" len)
    (bytes_to_str_hex plaintext_before)
    (bytes_to_str_hex plaintext)

let tail_length_cases encrypt =
  List.map
    (fun len ->
      Alcotest.test_case
        (Printf.sprintf "length = %d" len)
        `Quick
        (test_tail_length encrypt len))
    tail_lengths

let () =
  Alcotest.run "chacha20"
    [
      ( "rfc8439-vectors",
        [
          Alcotest.test_case "quarter_round" `Quick test_quarter_round;
          Alcotest.test_case "block_function" `Quick test_block_fn;
          Alcotest.test_case "quarter_round_scalar_unboxed" `Quick
            test_quarter_round_scalar_unboxed;
        ] );
      ( "rfc-encryption",
        [
          Alcotest.test_case "vanilla" `Quick
            (test_rfc_encryption Chacha20.Vanilla.encrypt);
          Alcotest.test_case "scalar_unboxed" `Quick
            (test_rfc_encryption Chacha20.Scalar_unboxed.encrypt);
          Alcotest.test_case "libsodium ietf" `Quick test_libsodium_encryption;
        ] );
      ( "differential-test-with-libsodium-ietf",
        [
          QCheck_alcotest.to_alcotest
            (test_differential_libsodium_ietf_encryption "vanilla"
               Chacha20.Vanilla.encrypt);
          QCheck_alcotest.to_alcotest
            (test_differential_libsodium_ietf_encryption "scalar unboxed"
               Chacha20.Scalar_unboxed.encrypt);
        ] );
      ("tail-lengths-vanilla", tail_length_cases Chacha20.Vanilla.encrypt);
      ( "tail-lengths-scalar-unboxed",
        tail_length_cases Chacha20.Scalar_unboxed.encrypt );
    ]
