val quarter_round : int32# array @ local -> int -> int -> int -> int -> unit

val encrypt :
  key:bytes ->
  counter:int32 ->
  nonce:bytes ->
  plaintext:bytes ->
  ciphertext:bytes ->
  unit
