(* Copyright 2023 - 2023, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

module type Json_encoding = sig

  type t

  val of_yojson : Yojson.Safe.t -> (t, string) result

  val to_yojson : t -> Yojson.Safe.t

end

module Make(KV: Mirage_kv.RW)(J: Json_encoding): Typed_kv.S
  with
    type value = J.t and
    type t = KV.t and
    type error = KV.error and
    type write_error = KV.write_error and
    type read_error = [ `Store of KV.error | `Json_decode of string ]
