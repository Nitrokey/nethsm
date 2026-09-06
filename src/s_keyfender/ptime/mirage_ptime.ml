(* Copyright 2023 - 2026, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

let now = Keyfender_clock.now
let now_d_ps () = Ptime.(Span.to_d_ps (to_span (now ())))
let current_tz_offset_s () = None
let period () = None
let period_d_ps () = None
