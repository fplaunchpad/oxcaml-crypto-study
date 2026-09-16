let rotl32 (x:int32) n : int32 =
  let open Int32 in
    let x = logor (shift_left x n) (shift_right_logical x (32 - n)) in
    x

let mat_add ~(initial_state: int32 array) ~(updated_state: int32 array) : unit =
  for i=0 to 15 do
    updated_state.(i) <- Int32.add initial_state.(i) updated_state.(i)
  done

let quarter_round (a,b,c,d): (int32 * int32 * int32 * int32) =
  let open Int32 in
    let a = add a b in
    let d = logxor d a in
    let d = rotl32 d 16 in

    let c = add c d in
    let b = logxor b c in
    let b = rotl32 b 12 in

    let a = add a b in
    let d = logxor d a in
    let d = rotl32 d 8 in

    let c = add c d in
    let b = logxor b c in
    let b = rotl32 b 7 in

    (a,b,c,d)

let inner_block(state: int32 array): unit =
  let qr_on_state (arr: int32 array) i j k l: unit =
    let (a,b,c,d) = quarter_round(arr.(i), arr.(j), arr.(k), arr.(l)) in
    arr.(i) <- a;
    arr.(j) <- b;
    arr.(k) <- c;
    arr.(l) <- d
  in
    qr_on_state state 0 4 8 12;
    qr_on_state state 1 5 9 13;
    qr_on_state state 2 6 10 14;
    qr_on_state state 3 7 11 15;
    qr_on_state state 0 5 10 15;
    qr_on_state state 1 6 11 12;
    qr_on_state state 2 7 8 13;
    qr_on_state state 3 4 9 14;;

let chacha20_block ~key ~counter ~nonce =
  let state: int32 array = Array.make 16 0l in
  state.(0) <- Int32.of_int 0x61707865;
  state.(1) <- Int32.of_int 0x3320646e;
  state.(2) <- Int32.of_int 0x79622d32;
  state.(3) <- Int32.of_int 0x6b206574;

  for i=0 to 7 do
    state.(i+4) <- Bytes.get_int32_le key (i*4)
  done;

  state.(12) <- counter;

  for i=0 to 2 do
    state.(i+13) <- Bytes.get_int32_le nonce (i*4)
  done;

  let initial_state = Array.copy state in
  for i=0 to 9 do
    inner_block state
  done;
  mat_add ~initial_state ~updated_state: state;

  let result = Bytes.create 64 in
  for i=0 to 15 do
    Bytes.set_int32_le result (i*4) state.(i)
  done;

  result

let encrypt ~key ~(counter:int32) ~nonce ~plaintext =
  let len = Bytes.length plaintext in
  let ciphertext = Bytes.create len in

  (** positive integer division floors by default *)
  for j=0 to len/64 - 1 do
    let key_stream = chacha20_block ~key ~counter:(Int32.add counter (Int32.of_int j)) ~nonce in
    for i=0 to 63 do
      let buf_idx = j * 64 + i in
      Bytes.set_int8 ciphertext buf_idx ((Bytes.get_int8 plaintext buf_idx) lxor (Bytes.get_int8 key_stream i));
    done;
  done;

  if len mod 64 <> 0 then
    let j = len/64 in
    let key_stream = chacha20_block ~key ~counter:(Int32.add counter (Int32.of_int j)) ~nonce in
    for i=0 to (len mod 64)-1 do
      let buf_idx = j * 64 + i in
      Bytes.set_int8 ciphertext buf_idx ((Bytes.get_int8 plaintext buf_idx) lxor (Bytes.get_int8 key_stream i));
    done;
  else ();

  ciphertext
