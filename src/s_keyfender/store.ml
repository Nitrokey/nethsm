open Lwt.Infix

(* a fake http implementation to avoid the paf and git-paf dependency, see
   https://github.com/mirage/ocaml-git/issues/513 *)
module Fake_http = struct
  type error = Not_implemented
  let pp_error ppf Not_implemented = Fmt.string ppf "HTTP not implemented"
  let get ~ctx:_ ?headers:_ _uri = Lwt.return_error Not_implemented
  let post ~ctx:_ ?headers:_ _uri _body = Lwt.return_error Not_implemented
end

let remote ?(ctx= Mimic.empty) ?headers:_ uri =
  match Smart_git.Endpoint.of_string uri with
  | Ok edn -> (ctx, edn)
  | Error (`Msg err) -> Fmt.invalid_arg "Invalid remote: %s" uri

module KV (G : Irmin_git.G) (C : Irmin.Contents.S) = struct
  include Irmin_git.KV (G) (Git.Mem.Sync (G)) (C)
  let remote ?ctx ?headers uri = E (remote ?ctx ?headers uri)
end

(* the following code originates from irmin-mirage-git 2.6.1 *)
(* modified to accomodate a push_and_pull (reducing memory usage) *)
module type KV_RO = sig
  type git

  include Mirage_kv.RO

  val connect :
    ?depth:int ->
    ?branch:string ->
    ?root:key ->
    ?ctx:Mimic.ctx ->
    ?headers:Cohttp.Header.t ->
    git ->
    string ->
    t Lwt.t
end

module KV_RO (G : Git.S) = struct
  module Key = Mirage_kv.Key

  type key = Key.t

  module G = struct
    include G

    let v ?dotgit:_ _root = assert false
  end

  module S = KV (G) (Irmin.Contents.String)
  module Sync = Irmin.Sync (S)

  let disconnect _ = Lwt.return_unit

  type error = [ Mirage_kv.error | S.write_error ]

  let pp_error ppf = function
    | #Mirage_kv.error as e -> Mirage_kv.pp_error ppf e
    | #S.write_error as e -> Irmin.Type.pp S.write_error_t ppf e

  let err e : ('a, error) result = Error e
  let err_not_found k = err (`Not_found k)

  let path x =
    (* XXX(samoht): we should probably just push the Key module in
         Irmin and remove the path abstraction completely ... *)
    Key.segments x

  module Tree = struct
    type t = { repo : S.repo; tree : S.tree }

    let digest t key =
      S.Tree.find_tree t.tree (path key) >|= function
      | None -> err_not_found key
      | Some tree ->
          let h = S.Tree.hash tree in
          Ok (Irmin.Type.to_string S.Hash.t h)

    let list t key =
      S.Tree.list t.tree (path key) >|= fun l ->
      let l =
        List.map
          (fun (s, k) ->
            ( s,
              match S.Tree.destruct k with
              | `Contents _ -> `Value
              | `Node _ -> `Dictionary ))
          l
      in
      Ok l

    let exists t key =
      S.Tree.kind t.tree (path key) >|= function
      | Some `Contents -> Ok (Some `Value)
      | Some `Node -> Ok (Some `Dictionary)
      | None -> Ok None

    let get t key =
      S.Tree.find t.tree (path key) >|= function
      | None -> err_not_found key
      | Some v -> Ok v
  end

  type t = { root : S.key; t : S.t }

  let head_message t =
    S.Head.find t.t >|= function
    | None -> "empty HEAD"
    | Some h ->
        let info = S.Commit.info h in
        Fmt.str "commit: %a\nAuthor: %s\nDate: %Ld\n\n%s\n" S.Commit.pp_hash h
          (Irmin.Info.author info) (Irmin.Info.date info)
          (Irmin.Info.message info)

  let last_modified t key =
    let key' = path key in
    S.last_modified t.t key' >|= function
    | [] -> Error (`Not_found key)
    | h :: _ -> Ok (0, Irmin.Info.date (S.Commit.info h))

  let connect ?depth ?(branch = "master") ?(root = Mirage_kv.Key.empty) ?ctx
      ?headers t uri =
    let remote = S.remote ?ctx ?headers uri in
    let head = Git.Reference.v ("refs/heads/" ^ branch) in
    S.repo_of_git ~bare:true ~head t >>= fun repo ->
    S.of_branch repo branch >>= fun t ->
    Sync.pull_exn t ?depth remote `Set >|= fun _ ->
    let root = path root in
    { t; root }

  let tree t =
    let repo = S.repo t.t in
    (S.find_tree t.t t.root >|= function
     | None -> S.Tree.empty ()
     | Some tree -> tree)
    >|= fun tree -> { Tree.repo; tree }

  let exists t k = tree t >>= fun t -> Tree.exists t k
  let get t k = tree t >>= fun t -> Tree.get t k
  let list t k = tree t >>= fun t -> Tree.list t k
  let digest t k = tree t >>= fun t -> Tree.digest t k

  let get t k =
    match Key.segments k with
    | [ "HEAD" ] -> head_message t >|= fun v -> Ok v
    | _ -> get t k
end

module type KV_RW = sig
  type git

  include Mirage_kv.RW

  val connect :
    ?depth:int ->
    ?branch:string ->
    ?root:key ->
    ?ctx:Mimic.ctx ->
    ?headers:Cohttp.Header.t ->
    ?author:(unit -> string) ->
    ?msg:([ `Set of key | `Remove of key | `Batch ] -> string) ->
    git ->
    string ->
    t Lwt.t
end

module KV_RW (G : Irmin_git.G) (C : Mirage_clock.PCLOCK) = struct
  (* XXX(samoht): batches are stored in memory. This could be bad if
       large objects are stored for too long... Might be worth having
       a clever LRU, which pushes larges objects to the underlying
       layer when needed. *)

  module Info = Irmin_mirage.Info (C)
  module RO = KV_RO (G)
  module S = RO.S
  module Tree = RO.Tree

  type batch = { repo : S.repo; mutable tree : S.tree; origin : S.commit }

  type store = Batch of batch | Store of RO.t

  type key = RO.key
  type error = RO.error

  type t = {
    mutable store : store;
    depth : int option;
    branch : string option;
    root : key option;
    ctx : Mimic.ctx option;
    headers : Cohttp.Header.t option;
    mutable git : G.t;
    uri : string;
    author : unit -> string;
    msg : [ `Set of RO.key | `Remove of RO.key | `Batch ] -> string;
    remote : Irmin.remote;
  }

  let pp_error = RO.pp_error
  let default_author () = "irmin <irmin@mirage.io>"

  let default_msg = function
    | `Set k -> Fmt.str "Updating %a" Mirage_kv.Key.pp k
    | `Remove k -> Fmt.str "Removing %a" Mirage_kv.Key.pp k
    | `Batch -> "Commmiting batch operation"

  let connect ?depth ?branch ?root ?ctx ?headers ?(author = default_author)
      ?(msg = default_msg) git uri =
    RO.connect ?depth ?branch ?root ?ctx ?headers git uri >|= fun t ->
    let remote = S.remote ?ctx ?headers uri in
    { store = Store t; depth ; branch ; root ; ctx ; headers ; git ; uri ;
      author; msg; remote }

  let disconnect t =
    match t.store with Store t -> RO.disconnect t | Batch _ -> Lwt.return_unit

  (* XXX(samoht): always return the 'last modified' on the
       underlying storage layer, not for the current batch. *)
  let last_modified t key =
    match t.store with
    | Store t -> RO.last_modified t key
    | Batch b ->
        RO.S.of_commit b.origin >>= fun t ->
        RO.last_modified { root = S.Key.empty; t } key

  let repo t = match t.store with Store t -> S.repo t.t | Batch b -> b.repo

  let tree t =
    match t.store with
    | Store t -> RO.tree t
    | Batch b -> Lwt.return { Tree.tree = b.tree; repo = repo t }

  let digest t k = tree t >>= fun t -> Tree.digest t k
  let exists t k = tree t >>= fun t -> Tree.exists t k
  let get t k = tree t >>= fun t -> Tree.get t k
  let list t k = tree t >>= fun t -> Tree.list t k

  type write_error = [ RO.error | Mirage_kv.write_error | RO.Sync.push_error ]

  let write_error = function
    | Ok _ -> Ok ()
    | Error e -> Error (e :> write_error)

  let pp_write_error ppf = function
    | #RO.error as e -> RO.pp_error ppf e
    | #RO.Sync.push_error as e -> RO.Sync.pp_push_error ppf e
    | #Mirage_kv.write_error as e -> Mirage_kv.pp_write_error ppf e

  let info t op = Info.f ~author:(t.author ()) "%s" (t.msg op)
  let path = RO.path

  let pushes = ref 0

  let push_and_pull t store =
    incr pushes;
    RO.Sync.push store.RO.t t.remote >>= fun r ->
    (if !pushes mod 100 = 0 then
       G.v (Fpath.v "somewhere") >>= function
       | Ok git ->
         RO.connect ?depth:t.depth ?branch:t.branch ?root:t.root ?ctx:t.ctx ?headers:t.headers t.git t.uri >|= fun store ->
         t.store <- Store store;
         t.git <- git
       | Error _ -> Lwt.return_unit
     else
       Lwt.return_unit) >|= fun () ->
    write_error r

  let set t k v =
    let info = info t (`Set k) in
    match t.store with
    | Store s -> (
        S.set ~info s.t (path k) v >>= function
        | Ok _ -> push_and_pull t s
        | Error e -> Lwt.return (Error (e :> write_error)))
    | Batch b ->
        S.Tree.add b.tree (path k) v >|= fun tree ->
        b.tree <- tree;
        Ok ()

  let remove t k =
    let info = info t (`Remove k) in
    match t.store with
    | Store s -> (
        S.remove ~info s.t (path k) >>= function
        | Ok _ -> push_and_pull t s
        | Error e -> Lwt.return (Error (e :> write_error)))
    | Batch b ->
        S.Tree.remove b.tree (path k) >|= fun tree ->
        b.tree <- tree;
        Ok ()

  let get_store_tree (t : RO.t) =
    S.Head.find t.t >>= function
    | None -> Lwt.return_none
    | Some origin -> (
        let tree = S.Commit.tree origin in
        S.Tree.find_tree tree t.root >|= function
        | Some t -> Some (origin, t)
        | None -> Some (origin, S.Tree.empty ()))

  let batch t ?(retries = 42) f =
    let info = info t `Batch in
    let one t =
      match t.store with
      | Batch _ -> Fmt.failwith "No recursive batches"
      | Store s -> (
          let repo = S.repo s.t in
          (* get the tree origin *)
          get_store_tree s >>= function
          | None -> f t >|= fun x -> Ok x (* no transaction is needed *)
          | Some (origin, old_tree) -> (
              let batch = { repo; tree = old_tree; origin } in
              let b = Batch batch in
              f { t with store = b } >>= fun result ->
              get_store_tree s >>= function
              | None ->
                  (* Someting weird happened, retring *)
                  Lwt.return (Error `Retry)
              | Some (_, main_tree) -> (
                  Irmin.Merge.f S.Tree.merge
                    ~old:(Irmin.Merge.promise old_tree)
                    main_tree batch.tree
                  >>= function
                  | Error (`Conflict _) -> Lwt.return (Error `Retry)
                  | Ok new_tree -> (
                      S.set_tree s.t ~info s.root new_tree >|= function
                      | Ok () -> Ok result
                      | Error _ -> Error `Retry))))
    in
    let rec loop = function
      | 0 -> Lwt.fail_with "Too many retries"
      | n -> (
          one t >>= function
          | Error `Retry -> loop (n - 1)
          | Ok r -> Lwt.return r)
    in
    loop retries >>= fun r ->
    match t.store with
    | Batch _ -> Fmt.failwith "No recursive batches"
    | Store s -> (
        push_and_pull t s >>= function
        | Ok _ -> Lwt.return r
        | Error e -> Lwt.fail_with (Fmt.to_to_string pp_write_error e))
end
