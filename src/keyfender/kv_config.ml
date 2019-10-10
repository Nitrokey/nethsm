(* unencrypted configuration store *)
module Make (KV : Mirage_kv_lwt.RW) = struct

  type t = KV.t

  let config_prefix = "config"

  let name = function
    | `Unlock_salt -> "unlock-salt"
    | `Certificate -> "public.pem"
    | `Private_key -> "key.pem"
    | `Version -> "version"

  let key_path key = Mirage_kv.Key.(add (v config_prefix) (name key))

  let get t key = KV.get t (key_path key)

  let set t key value = KV.set t (key_path key) value
end
