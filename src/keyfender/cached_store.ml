(* Copyright 2023 - 2023, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

open Lwt.Syntax

let ( let++ ) v f = Lwt_result.map f v

type settings = {
  refresh_delay_s : float option;
  evict_delay_s : float;
  cache_size : int;
}

module Make (KV : Typed_kv.S) (Monotonic_clock : Mirage_clock.MCLOCK) = struct
  type creation_time = int64

  module Cache =
    Lru.F.Make
      (struct
        type t = Mirage_kv.Key.t

        let compare = Mirage_kv.Key.compare
      end)
      (struct
        type t = KV.value * creation_time

        let weight _ = 1
      end)

  include KV

  type op = Set of (key * value) | Remove of key

  let default_settings =
    { refresh_delay_s = None; evict_delay_s = 30.; cache_size = 1024 }

  let s_to_ns s = Int64.of_float (1_000_000_000. *. s)

  type async_refresh = { request : key -> unit; cancel : unit -> unit }

  type cache = {
    mutable cache : Cache.t;
    settings : settings;
    async_refresh : async_refresh option;
  }

  type mode = Cache of cache | Batch of op list ref
  type t = { kv : KV.t; mode : mode }

  let clear_cache cache =
    match cache.mode with
    | Batch _ -> invalid_arg "Cached_store: cannot clear in batch mode"
    | Cache c -> c.cache <- Cache.empty c.settings.cache_size

  let update cache key value =
    Cache.add key (value, Monotonic_clock.elapsed_ns ()) cache

  type ('a, 'b) validation =
    | Up_to_date of 'a
    | Stale of ('a * 'b)
    | Invalid
    | Unknown

  let check ~settings ~async_refresh cache id =
    let now = Monotonic_clock.elapsed_ns () in
    let invalid_threshold = Int64.(sub now (s_to_ns settings.evict_delay_s)) in
    let stale_threshold =
      Option.bind async_refresh (fun async_refesh ->
          Option.map
            (fun refresh_delay ->
              (Int64.(sub now (s_to_ns refresh_delay)), async_refesh))
            settings.refresh_delay_s)
    in
    match (Cache.find id cache, stale_threshold) with
    | None, _ -> Unknown
    | Some (_, date), _ when Int64.compare date invalid_threshold < 0 -> Invalid
    | Some (v, date), Some (stale_threshold, async_refresh)
      when Int64.compare date stale_threshold < 0 ->
        Stale (v, async_refresh)
    | Some (v, _), _ -> Up_to_date v

  let rec refresh_loop ~settings ~kv ~cache stream =
    let* v = Lwt_stream.get stream in
    match v with
    | None -> Lwt.return ()
    | Some key ->
        let* result = KV.get kv key in
        (match
           (result, check ~settings ~async_refresh:(Some ()) cache.cache key)
         with
        | Ok value, (Stale _ | Invalid) ->
            cache.cache <- update cache.cache key value
        | Ok _, (Unknown | Up_to_date _) ->
            ()
            (* we only update when the value
               is still stale after fetching.
               This is to avoid race conditions
            *)
        | Error e, _ ->
            Logs.warn (fun f ->
                f "Failed to refresh stale value: %a" KV.pp_read_error e);
            cache.cache <- Cache.remove key cache.cache);
        refresh_loop ~settings ~kv ~cache stream

  let connect ?(settings = default_settings) kv =
    let async_refresh_stream =
      Option.map (fun _ -> Lwt_stream.create ()) settings.refresh_delay_s
    in
    let async_refresh =
      Option.map
        (fun (_, async_refresh_request) ->
          {
            request = (fun v -> async_refresh_request (Some v));
            cancel = (fun () -> async_refresh_request None);
          })
        async_refresh_stream
    in
    let cache =
      { cache = Cache.empty settings.cache_size; settings; async_refresh }
    in
    Option.iter
      (fun (async_refresh_stream, _) ->
        Lwt.dont_wait
          (fun () -> refresh_loop ~settings ~kv ~cache async_refresh_stream)
          (fun exn ->
            Logs.err (fun f ->
                f "Unexpected exception in cache refresh loop: %a" Fmt.exn exn);
            raise exn))
      async_refresh_stream;
    { kv; mode = Cache cache }

  let disconnect t =
    (match t.mode with
    | Cache t -> (
        match t.async_refresh with Some { cancel; _ } -> cancel () | _ -> ())
    | _ -> invalid_arg "Cannot disconnect batch device");
    KV.disconnect t.kv

  let list t = KV.list t.kv
  let last_modified t = KV.last_modified t.kv
  let digest t = KV.digest t.kv

  let batch t ?retries fn =
    match t.mode with
    | Batch _ -> Fmt.failwith "No recursive batches"
    | Cache c ->
        let ops = ref [] in
        let+ v =
          KV.batch t.kv ?retries (fun kv ->
              ops := [];
              fn { kv; mode = Batch ops })
        in
        (* If the batch operation succeeds, the cache is updated. *)
        List.iter
          (function
            | Remove key -> c.cache <- Cache.remove key c.cache
            | Set (key, value) -> c.cache <- update c.cache key value)
          !ops;
        c.cache <- Cache.trim c.cache;
        v

  (* Cached operations *)
  let get t id =
    match t.mode with
    | Batch _ -> KV.get t.kv id
    | Cache ({ cache; settings; async_refresh; _ } as c) -> (
        match check ~settings ~async_refresh cache id with
        | Up_to_date v -> Lwt.return_ok v
        | Stale (v, { request; _ }) ->
            request id;
            Lwt.return_ok v
        | (Invalid | Unknown) as check ->
            let++ value = KV.get t.kv id in
            c.cache <- update cache id value;
            if check = Unknown then c.cache <- Cache.trim c.cache;
            value)

  let exists t id =
    match t.mode with
    | Batch _ -> KV.exists t.kv id
    | Cache { cache; settings; async_refresh; _ } -> (
        match check ~settings ~async_refresh cache id with
        | Up_to_date _ -> Lwt.return_ok (Some `Value)
        | Stale (_, { request; _ }) ->
            request id;
            Lwt.return_ok (Some `Value)
        | Invalid | Unknown -> KV.exists t.kv id)

  (* Mutations have to update the cache *)
  let set t id value =
    let++ () = KV.set t.kv id value in
    match t.mode with
    | Cache ({ cache; _ } as c) -> c.cache <- update cache id value
    | Batch lst -> lst := Set (id, value) :: !lst

  let remove t id =
    let++ () = KV.remove t.kv id in
    match t.mode with
    | Cache ({ cache; _ } as c) -> c.cache <- Cache.remove id cache
    | Batch lst -> lst := Remove id :: !lst
end
