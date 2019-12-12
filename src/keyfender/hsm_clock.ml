module type HSMCLOCK = sig
  include Mirage_clock.PCLOCK
  val now : unit -> Ptime.t (* hw_clock with offset applied *)
  val now_raw : unit -> [ `Raw of Ptime.t ] (* hw_clock *)
  val get_offset : unit -> Ptime.Span.t
  val set : Ptime.t -> unit (* input time has offset applied, needs to be translated into offset relative to hw_clock *)
end

module Make(Hw_clock: Mirage_clock.PCLOCK) = struct
  let time_offset = ref Ptime.Span.zero

  let get_offset () = !time_offset

  let now_raw () = `Raw (Ptime.v (Hw_clock.now_d_ps ()))

  let now () =
    let `Raw hw_clock = now_raw () in
    match Ptime.add_span hw_clock !time_offset with
    | None -> Ptime.epoch
    | Some ts -> ts

  let set timestamp =
    let `Raw hw_clock = now_raw () in 
    let span = Ptime.diff timestamp hw_clock in
    time_offset := span

  let now_d_ps () = Ptime.(Span.to_d_ps @@ to_span @@ now ())

  let current_tz_offset_s () = None

  let period_d_ps () = None
end
