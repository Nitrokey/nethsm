open Lwt.Syntax
let (let++) v f = Lwt_result.map f v

module Make(KV: Typed_kv.S)(Time: Mirage_time.S)(Monotonic_clock : Mirage_clock.MCLOCK): 
sig 
  include Typed_kv.S with 
  type value = KV.value and 
  type error = KV.error and 
  type write_error = KV.write_error and
  type read_error = KV.read_error

  val connect : KV.t -> t
end = struct

  module Cache = Cachecache.Lru.Make(struct 
    type t = Mirage_kv.Key.t

    let hash = Hashtbl.hash

    let equal = Mirage_kv.Key.equal
  end)

  include KV 

  type op = Set of (key * value) | Remove of key

  type t = {
    kv: KV.t;
    cache: KV.value Cache.t;
    batch: op list ref option;
    timeout_ns: int64;
    mutable timeout_deadline_ns: int64;
  }

  let get_next_deadline timeout_ns =
    Int64.add (Monotonic_clock.elapsed_ns ()) timeout_ns

  let timeout_thread t =
    let rec aux () =
      let* () =
        Time.sleep_ns (Int64.sub t.timeout_deadline_ns (Monotonic_clock.elapsed_ns ())) 
      in
      if (Monotonic_clock.elapsed_ns () > t.timeout_deadline_ns) then
      begin
        t.timeout_deadline_ns <- get_next_deadline t.timeout_ns;
        Cache.clear t.cache
      end;
      aux () 
    in
    aux ()

  let connect kv = 
    let timeout_ns = 1_000_000_000L in
    let t = { kv; 
              cache = Cache.v 16; 
              batch = None;
              timeout_ns;
              timeout_deadline_ns = get_next_deadline timeout_ns}
    in
    Lwt.async (fun () -> timeout_thread t);
    t

  let disconnect t = KV.disconnect t.kv

  let list t = KV.list t.kv

  let last_modified t = KV.last_modified t.kv

  let digest t = KV.digest t.kv

  let batch t ?retries fn = 
    match t.batch with
    | Some _ -> Fmt.failwith "No recursive batches"
    | None ->
      let ops = ref [] in
      let+ v = KV.batch t.kv ?retries (fun kv -> 
        ops := []; 
        fn {  kv; 
              cache = t.cache; 
              batch = Some ops; 
              timeout_ns = t.timeout_ns; 
              timeout_deadline_ns = t.timeout_deadline_ns}) 
      in 
      (* If the batch operation succeeds, the cache is updated. *)
      List.iter (function
        | Remove key -> Cache.remove t.cache key 
        | Set (key, value) -> Cache.replace t.cache key value) !ops;
      v

  (* Cached operations *)
  let get t id = 
    match Cache.find_opt t.cache id with
    | Some v -> Lwt.return_ok v
    | None ->
      let++ value = KV.get t.kv id in
      Cache.replace t.cache id value;
      value

  let exists t id = 
    match Cache.mem t.cache id with
    | true -> Lwt.return_ok (Some `Value)
    | false -> KV.exists t.kv id

  (* Mutations have to update the cache *)
  let set t id value = 
    let++ () = KV.set t.kv id value in
    match t.batch with
    | None -> Cache.replace t.cache id value
    | Some lst -> lst := (Set (id, value)) :: !lst

  let remove t id =
    let++ () = KV.remove t.kv id in
    match t.batch with
    | None -> Cache.remove t.cache id
    | Some lst -> lst := (Remove id) :: !lst
  
end