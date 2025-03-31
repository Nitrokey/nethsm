(* Copyright 2023 - 2023, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

type settings = {
  refresh_delay_s : float option;
  evict_delay_s : float;
  cache_size : int;
}

module Make (KV : Kv_ext.Typed_ranged) : sig
  include
    Kv_ext.Typed_ranged
      with type value = KV.value
       and type error = KV.error
       and type write_error = KV.write_error
       and type read_error = KV.read_error

  val connect : ?settings:settings -> KV.t -> t
  val clear_cache : t -> unit
end
