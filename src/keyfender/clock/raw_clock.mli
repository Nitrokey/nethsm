(* Copyright 2023 - 2026, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

(** The hardware wall clock, uncorrected. This is the virtual module of
    [keyfender.clock]; it is internal to the library, [Keyfender_clock.now_raw]
    exposes it. *)

val now : unit -> [ `Raw of Ptime.t ]
(** [now ()] is the current reading of the hardware wall clock. The [`Raw] tag
    marks it as uncorrected so that it cannot be confused with the corrected
    wall clock time. *)
