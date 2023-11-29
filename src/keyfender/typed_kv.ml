(* Copyright 2023 - 2023, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

module type S = sig
  include Mirage_kv.RW

  type value
  type read_error

  val pp_read_error : read_error Fmt.t
  val get : t -> key -> (value, read_error) result Lwt.t
  val set : t -> key -> value -> (unit, write_error) result Lwt.t
end
