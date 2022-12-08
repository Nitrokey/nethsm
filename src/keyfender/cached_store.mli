
type settings = {
  refresh_delay_s: float option;
  evict_delay_s: float;
  cache_size: int;
}

module Make (KV : Typed_kv.S)(Monotonic_clock : Mirage_clock.MCLOCK) :
sig
  include Typed_kv.S with
    type value = KV.value and
    type error = KV.error and
    type write_error = KV.write_error and
    type read_error = KV.read_error


  val connect : ?settings:settings -> KV.t -> t

end
