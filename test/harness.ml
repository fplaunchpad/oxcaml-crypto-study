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
            let k = String.trim (String.sub line 0 (split_idx-1)) in
            let v = String.trim (String.sub line (split_idx+1) (String.length line - split_idx - 1)) in
            parse_vectors ((k,v)::li)
        | exception End_of_file -> li

      in parse_vectors []
    )

end
