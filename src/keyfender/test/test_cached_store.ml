
module Time = struct
  let sleep_ns duration = Lwt_unix.sleep (Duration.to_f duration)
end

module Hsm_clock = Keyfender.Hsm_clock.Make(Pclock)

module Stats_store(Store: Mirage_kv.RW) = struct 
  include Store
  let pp_read_error = pp_error

  type value = string

  type read_error = error

  type stats = {
    mutable reads: int;
    mutable writes: int;
  }

  type nonrec t = {
    t: t;
    stats: stats;
  }

  let get {t; stats} =
    stats.reads <- stats.reads + 1; 
    get t

  let set {t; stats} =
    stats.writes <- stats.writes + 1; 
    set t

  let disconnect {t; _} = disconnect t

  let exists {t; stats} k =
    stats.reads <- stats.reads + 1;
    exists t k

  let list {t; _} = list t

  let last_modified {t; _} = last_modified t

  let digest {t; _} = digest t

  let remove {t; _} = remove t

  let batch {t; stats} ?retries fn = 
    let batch_stats = {reads=0; writes=0} in
    let open Lwt.Syntax in
    let+ v = batch ?retries t (fun t -> fn {t; stats = batch_stats}) in
    stats.reads <- batch_stats.reads + stats.reads;
    stats.writes <- batch_stats.writes + stats.writes;
    v

  let connect t = {t; stats = {reads=0; writes=0}}
  
end

module KV = Mirage_kv_mem.Make(Hsm_clock)
module Underlying_store = Stats_store(KV)
module Cached_store = Keyfender.Cached_store.Make(Underlying_store)(Time)(Mclock)

open Lwt.Syntax

let key0 = Mirage_kv.Key.v "/key0"

let key1 = Mirage_kv.Key.v "/key1"

let read_error: Cached_store.read_error Alcotest.testable = (module 
  struct
    type t = Cached_store.read_error

    let equal = (=)

    let pp = Cached_store.pp_read_error
  end)

let read_result = Alcotest.(result string read_error)

let expect (store: Underlying_store.t) name ~reads ~writes =
  Alcotest.(check int) (name ^ ": reads") reads store.stats.reads;
  Alcotest.(check int) (name ^ ": writes") writes store.stats.writes

let init_store ?settings () =
  let* kv = KV.connect () in
  let underlying_store = Underlying_store.connect kv in
  let cached_store = Cached_store.connect ?settings underlying_store in
  let+ _ = Underlying_store.set underlying_store key0 "value" in
  expect underlying_store "init" ~reads:0 ~writes:1;
  (underlying_store, cached_store)

let read_is_cached = 
  Alcotest.test_case "read is cached" `Quick @@ fun () ->
  Lwt_main.run @@
  let* (underlying_store, cached_store) = init_store () in
  let* _ = Cached_store.get cached_store key0 in
  expect underlying_store "first read" ~reads:1 ~writes:1;
  let* _ = Cached_store.get cached_store key0 in 
  let* _ = Cached_store.get cached_store key0 in 
  let+ v = Cached_store.get cached_store key0 in 
  expect underlying_store "next reads are cached" ~reads:1 ~writes:1;
  Alcotest.check read_result "value is correct" (Ok "value") v

let exist_is_cached = 
  Alcotest.test_case "read is cached" `Quick @@ fun () ->
  Lwt_main.run @@
  let* (underlying_store, cached_store) = init_store () in
  let* _ = Cached_store.get cached_store key0 in
  expect underlying_store "call to read (k0)" ~reads:1 ~writes:1;
  let* k1_exist = Cached_store.exists cached_store key1 in
  expect underlying_store "call to exist (k1)" ~reads:2 ~writes:1;
  let+ cached_k0_exist = Cached_store.exists cached_store key0 in 
  expect underlying_store "exist(k0) is cached" ~reads:2 ~writes:1;
  Alcotest.(check bool) "k0: cached result is true" true (cached_k0_exist = Ok (Some `Value));
  Alcotest.(check bool) "k1: cached result is false" true (k1_exist = Ok None)
      
let writes_update_cache = 
  Alcotest.test_case "writes update the cache" `Quick @@ fun () ->
  Lwt_main.run @@
  let* (underlying_store, cached_store) = init_store () in
  let* _ = Cached_store.set cached_store key0 "new value" in
  expect underlying_store "write" ~reads:0 ~writes:2;
  let* v = Cached_store.get cached_store key0 in
  expect underlying_store "next read is cached" ~reads:0 ~writes:2;
  Alcotest.check read_result "value is correct" (Ok "new value") v;
  Lwt.return_unit

let remove_invalidate_cache = 
  Alcotest.test_case "remove invalidate the cache" `Quick @@ fun () ->
  Lwt_main.run @@
  let* (underlying_store, cached_store) = init_store () in
  let* _ = Cached_store.remove cached_store key0 in
  expect underlying_store "remove key0" ~reads:0 ~writes:1;
  let* k0_exists = Cached_store.exists cached_store key0 in 
  expect underlying_store "exists key0" ~reads:1 ~writes:1;
  Alcotest.(check bool) "k0 doesn't exist" true (k0_exists = Ok None);
  Lwt.return_unit

let batch_operations_are_cached_on_success =
  Alcotest.test_case "batch operations are cached on success" `Quick @@ fun () ->
  Lwt_main.run @@
  let* (underlying_store, cached_store) = init_store () in
  let* _ = Cached_store.batch cached_store (fun cached_store -> 
    let+ _ = Cached_store.set cached_store key0 "new value" in
    expect underlying_store "in batch" ~reads:0 ~writes:1)
  in
  expect underlying_store "batch done" ~reads:0 ~writes:2;
  let+ v = Cached_store.get cached_store key0 in
  expect underlying_store "read is cached" ~reads:0 ~writes:2;
  Alcotest.check read_result "value is correct" (Ok "new value") v

let time_based_eviction_mechanism =
  Alcotest.test_case "time-based eviction mechanism" `Quick @@ fun () ->
  Lwt_main.run @@
  let settings = {Cached_store.refresh_delay_s = 0.1; evict_delay_s = 0.2; cache_size = 16} in
  let* (underlying_store, cached_store) = init_store ~settings () in
  (* obtain a value *)
  let* initial_value = Cached_store.get cached_store key0 in
  expect underlying_store "first read" ~reads:1 ~writes:1;
  (* value is updated from the outside *)
  let* _ = Underlying_store.set underlying_store key0 "new value" in
  expect underlying_store "write" ~reads:1 ~writes:2;
  (* after 0.10s, old value is returned but stale, a new cache request is asynchronously dispatched *)
  let* () = Lwt_unix.sleep 0.10 in
  let* stale_value = Cached_store.get cached_store key0 in
  expect underlying_store "stale read, async request" ~reads:1 ~writes:2;
  (* after 0.15s, new cache request succeed, new value is obtained *)
  let* () = Lwt_unix.sleep 0.05 in
  expect underlying_store "async request ok" ~reads:2 ~writes:2;
  let* new_value = Cached_store.get cached_store key0 in
  expect underlying_store "cached read" ~reads:2 ~writes:2;
  (* after 0.35s, new value is expired, a synchronous cache request is performed *)
  let* _ = Underlying_store.set underlying_store key0 "new new value" in
  expect underlying_store "cached read" ~reads:2 ~writes:3;
  let* () = Lwt_unix.sleep 0.20 in
  let+ new_new_value = Cached_store.get cached_store key0 in
  expect underlying_store "expired read" ~reads:3 ~writes:3;
  Alcotest.check read_result "initial value is correct" (Ok "value") initial_value;
  Alcotest.check read_result "stale value is correct" (Ok "value") stale_value;
  Alcotest.check read_result "new value is correct" (Ok "new value") new_value;
  Alcotest.check read_result "new new value is correct" (Ok "new new value") new_new_value

let () =
  Printexc.record_backtrace true;
  Fmt_tty.setup_std_outputs ();
  Logs.set_reporter (Logs_fmt.reporter ());
  Logs.set_level (Some Debug);
  let open Alcotest in
  let tests = [
    "read", [
      read_is_cached;
      exist_is_cached;
    ];
    "invalidation", [
      writes_update_cache;
      remove_invalidate_cache
    ];
    "batch operations", [
      batch_operations_are_cached_on_success;
    ];
    "time-based eviction mechanism", [
      time_based_eviction_mechanism;
    ];
  ]
  in
  run ~argv:Sys.argv "cached store" tests