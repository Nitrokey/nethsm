(* Copyright 2023 - 2023, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

type t = V0

val compare : t -> t -> [ `Smaller | `Equal | `Greater ]

val to_string : t -> string

val of_string : string -> (t, [> `Msg of string ]) result

val pp : t Fmt.t

val current : t

val file : string

val filename : Mirage_kv.Key.t
