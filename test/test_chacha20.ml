let quarter_round_path = "../vectors/chacha20/quarter_round.txt";;

let test_quarter_round () =
  let open Harness.Testvector_file in
  let test_vecs = parse quarter_round_path in
  let v k = Int32.of_string (List.assoc k test_vecs) in
  let a, b, c, d =
    Chacha20.quarter_round (v "a_in", v "b_in", v "c_in", v "d_in")
  in
  Alcotest.(check int32) "a" (v "a_out") a;
  Alcotest.(check int32) "b" (v "b_out") b;
  Alcotest.(check int32) "c" (v "c_out") c;
  Alcotest.(check int32) "d" (v "d_out") d

let () =
  Alcotest.run "chacha20"
    [ ( "rfc8439-vectors"
      , [ Alcotest.test_case "quarter_round" `Quick test_quarter_round ] )
    ]
