let[@zero_alloc] first x = x+1

(* this function may alloc, used to verify OxCaml toolchain *)
(* let[@zero_alloc] second () = print_endline "hello world!" *)
