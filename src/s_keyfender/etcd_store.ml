open Lwt.Infix
open Rpc.Etcdserverpb
open Kv.Mvccpb

let etcd_store_src = Logs.Src.create "etcd_store"

module Log = (val Logs.src_log etcd_store_src : Logs.LOG)

module Etcd_api (Stack : Tcpip.Stack.V4V6) = struct
  module T = Stack.TCP
  module C = H2_mirage.Client (T)

  let etcd_port = 2379
  let persistent_connection = ref None

  let error_handler e =
    match e with
    | `Exn e -> raise e
    | `Malformed_response s ->
        failwith (Format.sprintf "Malformed response: %s" s)
    | `Invalid_response_body_length r ->
        failwith
          (Fmt.str "Invalid response body length: %a" H2.Response.pp_hum r)
    | `Protocol_error (c, s) ->
        failwith (Fmt.str "Protocol error %a: %s" H2.Error_code.pp_hum c s)

  let create_connection ~stack =
    T.create_connection (Stack.tcp stack)
      (Ipaddr.V4 (Key_gen.platform ()), etcd_port)
    >>= function
    | Error e -> failwith (Fmt.str "create TCP connection: %a" T.pp_error e)
    | Ok flow -> C.create_connection ~error_handler flow

  let connection ~stack =
    match !persistent_connection with
    | Some connection when C.is_closed connection = false ->
        Lwt.return connection
    | _ ->
        Log.warn (fun m -> m "Reconnecting to etcd...");
        create_connection ~stack >>= fun connection ->
        Log.warn (fun m -> m "Connection established.");
        persistent_connection := Some connection;
        Lwt.return connection

  let do_grpc ~stack ~service ~rpc ~request ~decode =
    let f s = s >|= decode in
    let handler = Grpc_lwt.Client.Rpc.unary ~f request in
    connection ~stack >>= fun connection ->
    Grpc_lwt.Client.call ~service ~rpc ~scheme:"http" ~handler
      ~do_request:(C.request connection ~error_handler)
      ()
    >|= function
    | Error e -> failwith (Fmt.to_to_string Grpc__Status.pp e)
    | Ok (Error e, _) ->
        failwith (Ocaml_protoc_plugin.Runtime.Runtime'.Result.show_error e)
    | Ok (Ok r, _) -> r

  let put stack ~(request : PutRequest.t) : PutResponse.t Lwt.t =
    let request =
      PutRequest.to_proto request |> Ocaml_protoc_plugin.Writer.contents
    in
    let decode = function
      | None -> failwith "No PutResponse"
      | Some s -> Ocaml_protoc_plugin.Reader.create s |> PutResponse.from_proto
    in
    do_grpc ~stack ~service:"etcdserverpb.KV" ~rpc:"Put" ~request ~decode

  let range stack ~(request : RangeRequest.t) : RangeResponse.t Lwt.t =
    let request =
      RangeRequest.to_proto request |> Ocaml_protoc_plugin.Writer.contents
    in
    let decode = function
      | None -> failwith "No RangeResponse"
      | Some s ->
          Ocaml_protoc_plugin.Reader.create s |> RangeResponse.from_proto
    in
    do_grpc ~stack ~service:"etcdserverpb.KV" ~rpc:"Range" ~request ~decode

  let delete_range stack ~(request : DeleteRangeRequest.t) :
      DeleteRangeResponse.t Lwt.t =
    let request =
      DeleteRangeRequest.to_proto request |> Ocaml_protoc_plugin.Writer.contents
    in
    let decode = function
      | None -> failwith "No DeleteRangeResponse"
      | Some s ->
          Ocaml_protoc_plugin.Reader.create s |> DeleteRangeResponse.from_proto
    in
    do_grpc ~stack ~service:"etcdserverpb.KV" ~rpc:"DeleteRange" ~request
      ~decode

  (* let compact ~ctx ~req =
     let uri = Request.build_uri "/v3/kv/compaction" in
     let body =
       Request.write_as_json_body Etcdserverpb_compaction_request.to_yojson req
     in
     C.call ~ctx `POST uri ~headers ~body >>= fun (resp, body) ->
     Request.read_json_body_as
       (JsonSupport.unwrap Etcdserverpb_compaction_response.of_yojson)
       resp body *)

  (* let txn ~ctx ~req =
     let uri = Request.build_uri "/v3/kv/txn" in
     let body =
       Request.write_as_json_body Etcdserverpb_txn_request.to_yojson req
     in
     C.call ~ctx `POST uri ~headers ~body >>= fun (resp, body) ->
     Request.read_json_body_as
       (JsonSupport.unwrap Etcdserverpb_txn_response.of_yojson)
       resp body *)
end

module KV_RO (Stack : Tcpip.Stack.V4V6) = struct
  module Key = Mirage_kv.Key
  module Etcd = Etcd_api (Stack)

  type t = { stack : Stack.t }
  type key = Key.t

  let etcd_try f =
    Lwt.catch
      (fun () -> f ())
      (function
        | Failure s -> Lwt.return (Error (`Etcd_error s)) | exn -> raise exn)

  let bytes_of_key k = Bytes.of_string (Key.to_string k)

  (* Calculate end of range for prefix. See
     https://etcd.io/docs/v3.5/learning/api/#key-ranges *)
  let end_of_prefix p =
    let rec inc b i =
      if i < 0 then Bytes.make 1 '\x00'
      else
        match Bytes.get b i with
        | '\xff' -> inc b (i - 1)
        | c ->
            Bytes.set b i Char.(chr (code c + 1));
            Bytes.sub b 0 (i + 1)
    in
    let p = Bytes.copy p in
    inc p (Bytes.length p - 1)

  let disconnect _ = Lwt.return_unit

  type error = [ `Etcd_error of string | Mirage_kv.error ]

  let pp_error ppf = function
    | #Mirage_kv.error as e -> Mirage_kv.pp_error ppf e
    | `Etcd_error s -> Fmt.pf ppf "Etcd_error: %s" s

  let last_modified t k =
    let key = bytes_of_key k in
    let request = RangeRequest.make ~key ~keys_only:true () in
    etcd_try (fun () ->
        Etcd.range t.stack ~request >|= fun resp ->
        match resp.kvs with
        | { KeyValue.mod_revision = i } :: _ -> Ok (0, Int64.of_int i)
        | _ -> Error (`Not_found k))

  let exists t k =
    let key = bytes_of_key k in
    let range_end = end_of_prefix key in
    let request = RangeRequest.make ~key ~range_end ~keys_only:true () in
    etcd_try (fun () ->
        Etcd.range t.stack ~request >|= fun resp ->
        match resp.kvs with
        | [] -> Ok None
        | l ->
            if List.exists (fun e -> Bytes.equal e.KeyValue.key key) l then
              Ok (Some `Value)
            else Ok (Some `Dictionary))

  let get t k =
    let key = bytes_of_key k in
    let request = RangeRequest.make ~key () in
    etcd_try (fun () ->
        Etcd.range t.stack ~request >|= fun resp ->
        match resp.kvs with
        | { KeyValue.value = s } :: _ -> Ok (Bytes.to_string s)
        | _ -> Error (`Not_found k))

  let list t k =
    let key = Bytes.of_string (Key.to_string k ^ "/") in
    let range_end = end_of_prefix key in
    let prefix_len = Bytes.length key in
    let request = RangeRequest.make ~key ~range_end ~keys_only:true () in
    etcd_try (fun () ->
        Etcd.range t.stack ~request >|= fun resp ->
        let rec acc_keys acc kvs =
          match kvs with
          | [] -> acc
          | { KeyValue.key = k } :: t ->
              let key = Bytes.to_string k in
              let key_len = String.length key in
              let key_no_prefix =
                String.sub key prefix_len (key_len - prefix_len)
              in
              acc_keys ((key_no_prefix, `Value) :: acc) t
        in
        let keys = acc_keys [] resp.kvs in
        Ok keys)

  let digest t k =
    let open Lwt_result.Infix in
    get t k >|= fun v -> Digestif.SHA256.(to_hex (digest_string v))

  let connect stack =
    let connection = { stack } in
    exists connection (Key.v ".doesnotexist") >|= function
    | Ok _ -> Ok connection
    | Error e -> Error e
end

module KV_RW (Stack : Tcpip.Stack.V4V6) = struct
  module RO = KV_RO (Stack)
  include RO

  type write_error = [ RO.error | Mirage_kv.write_error ]

  let pp_write_error ppf = function
    | #RO.error as e -> RO.pp_error ppf e
    | #Mirage_kv.write_error as e -> Mirage_kv.pp_write_error ppf e

  let set t k v =
    let key = bytes_of_key k in
    let value = Bytes.of_string v in
    let request = PutRequest.make ~key ~value () in
    etcd_try (fun () -> Etcd.put t.stack ~request >|= fun _resp -> Ok ())

  let remove t k =
    let key = bytes_of_key k in
    let range_end = end_of_prefix key in
    let request = DeleteRangeRequest.make ~key ~range_end () in
    etcd_try (fun () ->
        Etcd.delete_range t.stack ~request >|= fun resp ->
        if resp.deleted > 0 then Ok () else Error (`Not_found k))

  let batch t ?(retries = 42) f = f t
end
