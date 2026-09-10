(* Copyright 2023 - 2026, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

(* The clock itself lives in keyfender.clock (Keyfender_clock), so that the
   Mirage_ptime implementation of the unikernel can share it. Mirage_ptime.now
   is expected to be Keyfender_clock.now; it is used here rather than
   Keyfender_clock.now directly so that the tests can mock it. *)
let now () = Mirage_ptime.now ()
let now_raw = Keyfender_clock.now_raw
let set = Keyfender_clock.set
