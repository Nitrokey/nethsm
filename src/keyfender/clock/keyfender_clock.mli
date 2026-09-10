(* Copyright 2023 - 2026, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

(** The NetHSM wall clock.

    The hardware clock cannot be set. Instead, [set] stores an offset relative
    to it, and [now] adds that offset to every reading of the hardware clock.

    This library depends only on [ptime] so that an application can build its
    [Mirage_ptime] implementation on [now]; through it, all consumers of
    [Mirage_ptime.now] (syslog, console log, TLS, ...) observe the corrected
    wall clock. [Hsm_clock] in [keyfender] is the interface used by the rest of
    the system.

    The hardware clock is read through the virtual module [Raw_clock]. The
    application chooses the implementation; the default, [keyfender.clock.unix],
    reads the OS clock via [Ptime_clock]. *)

val now : unit -> Ptime.t
(** [now ()] is the corrected wall clock time: the hardware clock plus the
    offset stored by [set]. *)

val now_raw : unit -> [ `Raw of Ptime.t ]
(** [now_raw ()] is the current reading of the hardware wall clock, without the
    offset. *)

val set : Ptime.t -> unit
(** [set t] makes [now ()] return [t] right now by storing the difference
    between [t] and the hardware clock. *)
