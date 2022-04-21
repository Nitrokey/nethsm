open Lwt.Syntax
let (let++) v f = Lwt_result.map f v

module Make(KV: Typed_kv.S)(Time: Mirage_time.S)(Monotonic_clock : Mirage_clock.MCLOCK):
sig
  include Typed_kv.S with
    type value = KV.value and
    type error = KV.error and
    type write_error = KV.write_error and
    type read_error = KV.read_error

  type settings = {
    refresh_delay_s: int;
    evict_delay_s: int;
  }

  val connect : ?settings:settings -> KV.t -> t
end = struct

  module Cache = Cachecache.Lru.Make(struct
    type t = Mirage_kv.Key.t

    let hash = Hashtbl.hash

    let equal = Mirage_kv.Key.equal
  end)

  include KV

  type op = Set of (key * value) | Remove of key

  type settings = {
    refresh_delay_s: int;
    evict_delay_s: int;
  }

  let default_settings = {
    refresh_delay_s = 20;
    evict_delay_s = 30;
  }

  type creation_time = int64

  type mode =
    | Cache of {
      cache: (KV.value * creation_time) Cache.t;
      settings: settings;
    } 
    | Batch of op list ref

  type t = {
    kv: KV.t;
    mode: mode;
  }

  let connect ?(settings = default_settings) kv =
    { kv;
      mode = Cache {
        cache = Cache.v 16;
        settings
      }
    }

  let disconnect t = KV.disconnect t.kv

  let list t = KV.list t.kv

  let last_modified t = KV.last_modified t.kv

  let digest t = KV.digest t.kv

  let update cache key value = 
    Cache.replace cache key (value, Monotonic_clock.elapsed_ns ())

  let batch t ?retries fn =
    match t.mode with
    | Batch _ -> Fmt.failwith "No recursive batches"
    | Cache {cache; _} ->
      let ops = ref [] in
      let+ v = KV.batch t.kv ?retries (fun kv ->
        ops := [];
        fn {  kv;
              mode = Batch ops; })
      in
      (* If the batch operation succeeds, the cache is updated. *)
      List.iter (function
        | Remove key -> Cache.remove cache key
        | Set (key, value) -> update cache key value) !ops;
      v

  (* Cached operations *)
  let get t id =
    match t.mode with
    | Batch _ -> KV.get t.kv id
    | Cache {cache; _} -> 
      match Cache.find_opt cache id with
      | Some (v, _) -> Lwt.return_ok v
      | None ->
        let++ value = KV.get t.kv id in
        update cache id value;
        value

  let exists t id =
    match t.mode with
    | Batch _ -> KV.exists t.kv id
    | Cache {cache; _} -> 
      match Cache.mem cache id with
      | true -> Lwt.return_ok (Some `Value)
      | false -> KV.exists t.kv id

  (* Mutations have to update the cache *)
  let set t id value =
    let++ () = KV.set t.kv id value in
    match t.mode with
    | Cache {cache; _} -> update cache id value
    | Batch lst -> lst := (Set (id, value)) :: !lst

  let remove t id =
    let++ () = KV.remove t.kv id in
    match t.mode with
    | Cache {cache; _} -> Cache.remove cache id
    | Batch lst -> lst := (Remove id) :: !lst

end
