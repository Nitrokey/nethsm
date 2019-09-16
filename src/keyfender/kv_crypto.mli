
module Make (R : Mirage_random.C) (KV : Mirage_kv_lwt.RW) : sig
  include Mirage_kv_lwt.RW

  val connect : ?prefix:string -> key:Cstruct.t -> KV.t -> t
end
