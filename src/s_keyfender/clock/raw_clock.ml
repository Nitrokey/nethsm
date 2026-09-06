(* Copyright 2023 - 2026, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

(* solo5_clock_wall () returns nanoseconds since the epoch; see
   keyfender_clock_stubs.c. Native code gets the result unboxed, without
   allocation. *)
external clock_wall_ns : unit -> (int64[@unboxed])
  = "keyfender_clock_wall_byte" "keyfender_clock_wall_native"
[@@noalloc]

let ns_per_day = 86_400_000_000_000L

let now () =
  let ns = clock_wall_ns () in
  let d = Int64.(to_int (div ns ns_per_day)) in
  let ps = Int64.(mul (rem ns ns_per_day) 1_000L) in
  match Option.bind (Ptime.Span.of_d_ps (d, ps)) Ptime.of_span with
  | Some t -> `Raw t
  | None -> `Raw Ptime.epoch
