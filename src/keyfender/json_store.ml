(* Copyright 2023 - 2023, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

module type Json_encoding = sig
  type t

  val of_yojson : Yojson.Safe.t -> (t, string) result
  val to_yojson : t -> Yojson.Safe.t
end

module Make (KV : Kv_ext.Ranged) (J : Json_encoding) :
  Kv_ext.Typed_ranged
    with type value = J.t
     and type t = KV.t
     and type error = KV.error
     and type write_error = KV.write_error
     and type read_error = [ `Store of KV.error | `Json_decode of string ] =
struct
  include KV

  type value = J.t
  type read_error = [ `Store of error | `Json_decode of string ]

  let get store id =
    let open Lwt.Infix in
    KV.get store id >|= function
    | Error e -> Error (`Store e)
    | Ok data ->
        Rresult.R.reword_error
          (fun err -> `Json_decode err)
          (Json.decode J.of_yojson data)

  let set store id value =
    let value_str = Yojson.Safe.to_string (J.to_yojson value) in
    KV.set store id value_str

  let pp_read_error ppf = function
    | `Store kv -> KV.pp_error ppf kv
    | `Json_decode msg -> Fmt.pf ppf "json decode failure %s" msg
end
