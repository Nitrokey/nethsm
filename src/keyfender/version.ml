(* Copyright 2023 - 2023, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

type t = V0 | V1

let compare ours stored =
  match (ours, stored) with
  | V0, V0 | V1, V1 -> `Equal
  | V0, V1 -> `Smaller
  | V1, V0 -> `Greater

let to_string = function V0 -> "0" | V1 -> "1"
let pp ppf v = Fmt.string ppf (to_string v)

let of_string = function
  | "0" -> Ok V0
  | "1" -> Ok V1
  | s -> Rresult.R.error_msgf "unknown version %S" s

  (* TODO clarify and write down semantics *)

let current = V1
let file = ".version"
let filename = Mirage_kv.Key.v file
