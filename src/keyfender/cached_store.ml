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
    cache_size: int;
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
    cache_size: int;
  }

  let default_settings = {
    refresh_delay_s = 20;
    evict_delay_s = 30;
    cache_size = 16;
  }

  type creation_time = int64

  let s_to_ns s =
    Int64.mul 
      (Int64.of_int s)
      1_000_000_000L

  type mode =
    | Cache of {
      cache: (KV.value * creation_time) Cache.t;
      settings: settings;
      async_refresh_request: (key -> unit);
    } 
    | Batch of op list ref

  type t = {
    kv: KV.t;
    mode: mode;
  }

  let update cache key value = 
    Cache.replace cache key (value, Monotonic_clock.elapsed_ns ())

  let rec refresh_loop ~kv ~cache stream =
    let* v = Lwt_stream.get stream in
    match v with
    | None -> Lwt.return ()
    | Some key ->
      let* result = KV.get kv key in
      (match result with
      | Ok value -> update cache key value
      | Error _ -> Cache.remove cache key);
      refresh_loop ~kv ~cache stream

  let connect ?(settings = default_settings) kv =
    let async_refresh_stream, async_refresh_request = Lwt_stream.create () in
    let cache = Cache.v settings.cache_size in
    Lwt.async (fun () -> refresh_loop ~kv ~cache async_refresh_stream);
    { kv;
      mode = Cache {
        cache;
        settings;
        async_refresh_request = fun v -> async_refresh_request (Some v);
      }
    }

  let disconnect t = KV.disconnect t.kv

  let list t = KV.list t.kv

  let last_modified t = KV.last_modified t.kv

  let digest t = KV.digest t.kv

  type 'a validation = 
    | Up_to_date of 'a
    | Stale of 'a
    | Invalid

  let check ~settings cache id =
    let now = Monotonic_clock.elapsed_ns () in
    let invalid_threshold = Int64.(sub now (s_to_ns settings.evict_delay_s)) in
    let stale_threshold = Int64.(sub now (s_to_ns settings.refresh_delay_s)) in
    match Cache.find_opt cache id with
    | None -> Invalid
    | Some (_, date) when Int64.compare date invalid_threshold < 0 -> Invalid 
    | Some (v, date) when Int64.compare date stale_threshold < 0 -> Stale v
    | Some (v, _) -> Up_to_date v

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
    | Cache {cache; settings; async_refresh_request} -> 
      match check ~settings cache id with
      | Up_to_date v -> Lwt.return_ok v
      | Stale v -> 
        async_refresh_request id;
        Lwt.return_ok v
      | Invalid ->
        let++ value = KV.get t.kv id in
        update cache id value;
        value

  let exists t id =
    match t.mode with
    | Batch _ -> KV.exists t.kv id
    | Cache {cache; settings; async_refresh_request} -> 
      match check ~settings cache id with
      | Up_to_date _ -> Lwt.return_ok (Some `Value)
      | Stale _ -> 
        async_refresh_request id;
        Lwt.return_ok (Some `Value)
      | Invalid -> KV.exists t.kv id

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
