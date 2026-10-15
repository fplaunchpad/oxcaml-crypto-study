module I = Stdlib_upstream_compatible.Int32_u

let[@zero_alloc] copy_unboxed_array_16l ~(src : int32# array)
    ~(dst : int32# array) =
  let open Int32_u_array in
  for i = 0 to 15 do
    dst.%(i) <- src.%(i)
  done

let[@zero_alloc] rotl32 (x : int32#) n : int32# =
  let x = I.logor (I.shift_left x n) (I.shift_right_logical x (32 - n)) in
  x

let[@zero_alloc] mat_add ~(initial_state : int32# array)
    ~(updated_state : int32# array) : unit =
  let open Int32_u_array in
  for i = 0 to 15 do
    updated_state.%(i) <- I.add initial_state.%(i) updated_state.%(i)
  done

let[@zero_alloc] quarter_round arr a b c d =
  let open I in
  let open Int32_u_array in
  arr.%(a) <- add arr.%(a) arr.%(b);
  arr.%(d) <- logxor arr.%(d) arr.%(a);
  arr.%(d) <- rotl32 arr.%(d) 16;

  arr.%(c) <- add arr.%(c) arr.%(d);
  arr.%(b) <- logxor arr.%(b) arr.%(c);
  arr.%(b) <- rotl32 arr.%(b) 12;

  arr.%(a) <- add arr.%(a) arr.%(b);
  arr.%(d) <- logxor arr.%(d) arr.%(a);
  arr.%(d) <- rotl32 arr.%(d) 8;

  arr.%(c) <- add arr.%(c) arr.%(d);
  arr.%(b) <- logxor arr.%(b) arr.%(c);
  arr.%(b) <- rotl32 arr.%(b) 7

let[@zero_alloc] inner_block (state : int32# array) : unit =
  quarter_round state 0 4 8 12;
  quarter_round state 1 5 9 13;
  quarter_round state 2 6 10 14;
  quarter_round state 3 7 11 15;
  quarter_round state 0 5 10 15;
  quarter_round state 1 6 11 12;
  quarter_round state 2 7 8 13;
  quarter_round state 3 4 9 14

let[@zero_alloc] prepare_keystream ~counter ~final_state ~initial_state =
  let open Int32_u_array in
  copy_unboxed_array_16l ~src:initial_state ~dst:final_state;
  final_state.%(12) <- counter;
  initial_state.%(12) <- counter;

  for _ = 0 to 9 do
    inner_block final_state
  done;

  mat_add ~initial_state ~updated_state:final_state

let[@zero_alloc] encrypt ~key ~counter ~nonce ~plaintext ~ciphertext =
  let open Int32_u_array in
  let initial_state =
    stack_
      [|
        #0l;
        #0l;
        #0l;
        #0l;
        #0l;
        #0l;
        #0l;
        #0l;
        #0l;
        #0l;
        #0l;
        #0l;
        #0l;
        #0l;
        #0l;
        #0l;
      |]
  in
  let final_state =
    stack_
      [|
        #0l;
        #0l;
        #0l;
        #0l;
        #0l;
        #0l;
        #0l;
        #0l;
        #0l;
        #0l;
        #0l;
        #0l;
        #0l;
        #0l;
        #0l;
        #0l;
      |]
  in

  initial_state.%(0) <- #0x61707865l;
  initial_state.%(1) <- #0x3320646el;
  initial_state.%(2) <- #0x79622d32l;
  initial_state.%(3) <- #0x6b206574l;

  (* TODO: Verify *)
  (* Bytes.get_int32_le is implemented with the %caml_bytes_get32 primitive and I.of_int32 is %unbox_int32. The compiler normally removes a box immediately followed by an unbox, so there's no allocation. *)
  for i = 0 to 7 do
    initial_state.%(i + 4) <- I.of_int32 (Bytes.get_int32_le key (i * 4))
  done;

  for i = 0 to 2 do
    initial_state.%(i + 13) <- I.of_int32 (Bytes.get_int32_le nonce (i * 4))
  done;

  let len = Bytes.length plaintext in

  (* positive integer division floors by default *)
  for j = 0 to (len / 64) - 1 do
    let cur_counter_unboxed = I.add (I.of_int32 counter) (I.of_int j) in
    prepare_keystream ~counter:cur_counter_unboxed ~final_state ~initial_state;

    for i = 0 to 15 do
      let buf_idx = (j * 64) + (i * 4) in
      Bytes.set_int32_le ciphertext buf_idx
        (Int32.logxor
           (Bytes.get_int32_le plaintext buf_idx)
           (I.to_int32 final_state.%(i)))
    done
  done;

  if len mod 64 <> 0 then (
    let j = len / 64 in

    let cur_counter_unboxed = I.add (I.of_int32 counter) (I.of_int j) in
    prepare_keystream ~counter:cur_counter_unboxed ~final_state ~initial_state;

    let remaining_bytes = len mod 64 in
    let remaining_quads = remaining_bytes / 4 in
    let leftover_bytes = len mod 4 in

    for i = 0 to remaining_quads - 1 do
      let buf_idx = (j * 64) + (i * 4) in
      Bytes.set_int32_le ciphertext buf_idx
        (Int32.logxor
           (Bytes.get_int32_le plaintext buf_idx)
           (I.to_int32 final_state.%(i)))
    done;

    let final_key_32 = I.to_int final_state.%(remaining_quads) in

    for i = 0 to leftover_bytes - 1 do
      let masked_key = (final_key_32 lsr (i * 8)) land 0x000000FF in
      let buf_idx = (j * 64) + (remaining_quads * 4) + i in
      Bytes.set_int8 ciphertext buf_idx
        (Bytes.get_int8 plaintext buf_idx lxor masked_key)
    done)
  else ()
