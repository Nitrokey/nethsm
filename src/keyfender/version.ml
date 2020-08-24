type t = V0

let compare ours stored = match ours, stored with
  | V0, V0 -> `Equal

let to_string = function V0 -> "0"

let pp ppf v = Fmt.string ppf (to_string v)

let of_string = function
  | "0" -> Ok V0
  | s -> Rresult.R.error_msgf "unknown version %S" s

let current = V0

let filename = Mirage_kv.Key.v ".version"
