let quarter_round_path = "../vectors/chacha20/quarter_round.txt"
let block_fn_path = "../vectors/chacha20/block_function.txt"
let encryption_path = "../vectors/chacha20/encryption.txt"

let test_quarter_round () =
  let open Harness.Testvector_file in
  let test_vecs = parse quarter_round_path in
  let v k = Int32.of_string ("0x" ^ List.assoc k test_vecs) in
  let a, b, c, d =
    Chacha20.quarter_round (v "a_in", v "b_in", v "c_in", v "d_in")
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

  let result = Chacha20.chacha20_block ~key ~counter ~nonce in
  Alcotest.(check string) "block_function" expected_out (bytes_to_str_hex result)

let test_encryption () =
  let open Harness.Testvector_file in
  let test_vals = parse encryption_path in
  
  let key = str_hex_to_bytes (List.assoc "Key" test_vals) in
  let nonce = str_hex_to_bytes (List.assoc "Nonce" test_vals) in
  let counter = Int32.of_string ("0x" ^ List.assoc "InitialCounter" test_vals) in
  let plaintext = str_hex_to_bytes (List.assoc "Plaintext" test_vals) in
  let expected_ciphertext = format_str (List.assoc "Ciphertext" test_vals) in

  let ciphertext = Chacha20.encrypt ~key ~counter ~nonce ~plaintext in
  Alcotest.(check string) "encryption" expected_ciphertext (bytes_to_str_hex ciphertext)

let () =
  Alcotest.run "chacha20"
    [ ( "rfc8439-vectors"
      , [ Alcotest.test_case "quarter_round" `Quick test_quarter_round;
      Alcotest.test_case "block_function" `Quick test_block_fn;
      Alcotest.test_case "encryption" `Quick test_encryption] )
    ]
