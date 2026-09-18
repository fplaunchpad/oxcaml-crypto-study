module Testvector_file = struct
  type t = (string * string) list;;

  let parse (path : string) : (string * string) list =
    In_channel.with_open_text path (fun in_ch ->
      let rec parse_vectors li =
        match input_line in_ch with
        | line ->
          if String.length line = 0 || line.[0] = '#' then
            parse_vectors li
          else
            let split_idx = String.index line '=' in
            let k = String.trim (String.sub line 0 (split_idx)) in
            let v = String.trim (String.sub line (split_idx+1) (String.length line - split_idx - 1)) in
            parse_vectors ((k,v)::li)
        | exception End_of_file -> li

      in parse_vectors []
    )

  let format_str s =
    let is_hex_digit ch = (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F') || (ch >= '0' && ch <= '9') in
    String.to_seq s |> Seq.filter is_hex_digit |> String.of_seq

  let str_hex_to_bytes s =
    let str = format_str s in
    let len = String.length str in
    let res = Bytes.create (len/2) in
    for i=0 to (len/2 - 1) do
      let byte = Char.chr (int_of_string("0x" ^ String.sub str (i*2) 2)) in
      Bytes.set res i byte
    done;
    res

  let bytes_to_str_hex b =
    let len = Bytes.length b in
    let res = Buffer.create (len * 2) in
    for i=0 to (len - 1) do
      let byte = Bytes.get b i in
      let str_hex = Printf.sprintf "%02x" (Char.code byte) in
      Buffer.add_string res str_hex
    done;
    Buffer.contents res

end

module Chacha20_qcheck_gen = struct
  let boundary_lengths = [ 0; 1; 63; 64; 65; 255; 256; 257 ]
  let large_lengths = [ 1_048_576; 4_194_304 ]

  let length_gen : int QCheck.Gen.t =
    QCheck.Gen.(
      oneof_weighted
        [ (6, oneof_list boundary_lengths)
        ; (3, int_range 0 4096)
        ; (1, oneof_list large_lengths)
        ])

  let key_gen : bytes QCheck.Gen.t = QCheck.Gen.bytes_size (QCheck.Gen.return 32)
  let nonce_gen : bytes QCheck.Gen.t = QCheck.Gen.bytes_size (QCheck.Gen.return 12)
  let counter_gen : int32 QCheck.Gen.t =
    QCheck.Gen.map Int32.of_int (QCheck.Gen.int_range 0 1_000_000)
  let plaintext_gen : bytes QCheck.Gen.t =
    QCheck.Gen.(length_gen >>= fun n -> bytes_size (return n))

  let gen : (bytes * bytes * int32 * bytes) QCheck.Gen.t =
    QCheck.Gen.quad key_gen nonce_gen counter_gen plaintext_gen

  let arbitrary = QCheck.make gen
end
