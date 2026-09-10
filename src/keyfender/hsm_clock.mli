(* Copyright 2023 - 2026, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

val now : unit -> Ptime.t
(** [now ()] is the corrected wall clock time ([Mirage_ptime.now]). *)

val now_raw : unit -> [ `Raw of Ptime.t ]
(** [now_raw ()] is the uncorrected hardware clock. Only needed to interpret
    offsets that were stored relative to it (migration of the deprecated
    time-offset config key); use [Mirage_mtime.elapsed_ns] to measure durations.
*)

val set : Ptime.t -> unit
(** [set t] makes [now ()] return [t] by storing the difference between [t] and
    the hardware clock. *)
