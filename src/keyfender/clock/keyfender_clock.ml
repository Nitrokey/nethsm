(* Copyright 2023 - 2026, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

let offset = ref Ptime.Span.zero
let get_offset () = !offset
let now_raw () = Raw_clock.now ()

let now () =
  let (`Raw raw) = now_raw () in
  match Ptime.add_span raw !offset with Some t -> t | None -> raw

let set timestamp =
  let (`Raw hw_clock) = now_raw () in
  offset := Ptime.diff timestamp hw_clock
