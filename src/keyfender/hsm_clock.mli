(* Copyright 2023 - 2023, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

val now : unit -> Ptime.t (* hw_clock with offset applied *)
val now_raw : unit -> [ `Raw of Ptime.t ] (* hw_clock *)
val get_offset : unit -> Ptime.Span.t
val set : Ptime.t -> unit
(* input time has offset applied, needs to be translated into offset relative to hw_clock *)
