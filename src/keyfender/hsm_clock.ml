(* Copyright 2023 - 2023, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

let time_offset = ref Ptime.Span.zero
let get_offset () = !time_offset
let now_raw () = `Raw (Mirage_ptime.now ())

let now () =
  let (`Raw hw_clock) = now_raw () in
  match Ptime.add_span hw_clock !time_offset with
  | None -> Ptime.epoch
  | Some ts -> ts

let set timestamp =
  let (`Raw hw_clock) = now_raw () in
  let span = Ptime.diff timestamp hw_clock in
  time_offset := span
