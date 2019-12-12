module type HSMCLOCK = sig
  include Mirage_clock.PCLOCK
  val now : unit -> Ptime.t (* hw_clock with offset applied *)
  val now_raw : unit -> [ `Raw of Ptime.t ] (* hw_clock *)
  val get_offset : unit -> Ptime.Span.t
  val set : Ptime.t -> unit (* input time has offset applied, needs to be translated into offset relative to hw_clock *)
end

module Make (Pclock : Mirage_clock.PCLOCK) : sig
  include HSMCLOCK
end
