let rotl32 (x:int32) n : int32 =
  let open Int32 in
    let x = logor (shift_left x n) (shift_right_logical x (32 - n)) in
    x

let quarter_round (a,b,c,d): (int32 * int32 * int32 * int32) =
  let () = Printf.printf "Initial: %#lx %#lx %#lx %#lx\n" a b c d in
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

    let () = Printf.printf "Initial: %#lx %#lx %#lx %#lx\n" a b c d in
    (a,b,c,d)

