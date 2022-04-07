let (let**) = Lwt_result.bind


module Make(KV: Typed_kv.S): sig 
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

  type t = {
    kv: KV.t;
    cache: KV.value Cache.t;
    batch: bool;
  }

  let connect kv = {kv; cache = Cache.v 16; batch = false}

  let disconnect t = KV.disconnect t.kv

  let list t = KV.list t.kv

  let last_modified t = KV.last_modified t.kv

  let digest t = KV.digest t.kv

  let batch t ?retries fn = 
    if t.batch then
      Fmt.failwith "No recursive batches"
    else
      KV.batch t.kv ?retries (fun kv -> fn {kv; cache = t.cache; batch = true})

  (* Cached operations *)

  let get t id = 
    match Cache.find_opt t.cache id with
    | Some v -> Lwt.return_ok v
    | None ->
      let** value = KV.get t.kv id in
      Cache.replace t.cache id value;
      Lwt.return_ok value

  let exists t id = 
    match Cache.mem t.cache id with
    | true -> Lwt.return_ok (Some `Value)
    | false -> KV.exists t.kv id

  (* Mutations have to update the cache *)
  let set t id value = 
    let** () = KV.set t.kv id value in
    if not t.batch then
      Cache.replace t.cache id value;
    Lwt.return_ok ()

  let remove t id =
    let** () = KV.remove t.kv id in
    if not t.batch then
      Cache.remove t.cache id;
    Lwt.return_ok ()
  
end