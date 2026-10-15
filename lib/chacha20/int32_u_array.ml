external get : int32# array -> int -> int32# = "%array_safe_get"
external set : int32# array -> int -> int32# -> unit = "%array_safe_set"
external ( .%() ) : int32# array -> int -> int32# = "%array_safe_get"

external ( .%()<- ) : int32# array -> int -> int32# -> unit
  = "%array_safe_set"

external uget : int32# array -> int -> int32# = "%array_unsafe_get"
external uset : int32# array -> int -> int32# -> unit = "%array_unsafe_set"
external len : int32# array -> int = "%array_length"
external make : int -> int32# -> int32# array = "%makearray_dynamic"

let copy_array_16l ~(src: int32# array) ~(dst: int32# array) =
  for i = 0 to 15 do
    dst.%(i) <- src.%(i)
  done

