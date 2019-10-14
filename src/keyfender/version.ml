type t = V0

let compare ours stored = match ours, stored with
  | V0, V0 -> `Equal

let to_string = function V0 -> "0"

let of_string = function
  | "0" -> Ok V0
  | s -> Error (`Msg ("unknown version " ^ s))

let current = V0
