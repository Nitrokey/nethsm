(* Copyright 2023 - 2023, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

open Lwt.Infix
(* open Rpc.Etcdserverpb
open Kv.Mvccpb *)
(* open Etcd_client *)

open Etcd_client.Rpc.Etcdserverpb
open Etcd_client.Kv.Mvccpb

let etcd_store_src = Logs.Src.create "etcd_store"

module Log = (val Logs.src_log etcd_store_src : Logs.LOG)

exception Etcd_error of string

let etcd_err s = raise (Etcd_error s)

module Etcd_api (Stack : Tcpip.Stack.V4V6) = struct
  module TCP = Stack.TCP
  module H2C = H2_lwt.Client (Gluten_mirage.Client (TCP))

  let etcd_port = 2379
  let persistent_connection = ref None
  let last_known_revision = ref 0L
  let set_persistent_connection x = persistent_connection := Some x
  let connection_established_callbacks = ref []

  let shutdown_connection conn =
    match H2C.is_closed conn with
    | true -> Lwt.return_unit
    | false ->
        Log.info (fun m -> m "shutting down connection");
        H2C.shutdown conn

  let shutdown_persistent_connection () =
    match !persistent_connection with
    | None -> ()
    | Some (conn, _err) ->
        persistent_connection := None;
        Lwt.async (fun () -> shutdown_connection conn)

  let persistent_connection () =
    match !persistent_connection with
    | Some (conn, err) ->
        if (not (H2C.is_closed conn)) && Lwt.state err == Lwt.Sleep then
          Some (conn, err)
        else (
          shutdown_persistent_connection ();
          None)
    | None -> None

  let error_to_string e =
    match e with
    | `Exn e -> Printexc.to_string e
    | `Malformed_response s -> Format.sprintf "malformed response: %s" s
    | `Invalid_response_body_length r ->
        Fmt.str "invalid response body length: %a" H2.Response.pp_hum r
    | `Protocol_error (c, s) ->
        Fmt.str "protocol error %a: %s" H2.Error_code.pp_hum c s

  let timeout sec msg =
    let rec loop sec =
      if sec = 0 then Lwt.return_unit
      else
        Mirage_sleep.ns (Duration.of_sec 1) >>= fun () ->
        (loop [@tailcall]) (sec - 1)
    in
    loop sec >>= fun () ->
    Log.err (fun m -> m "%s" msg);
    shutdown_persistent_connection ();
    Lwt.return msg

  let create_flow ~stack =
    Lwt.pick
      [
        TCP.create_connection (Stack.tcp stack)
          (Ipaddr.V4 (Args.platform ()), etcd_port);
        ( timeout 120 "TCP connection to etcd timed out" >|= fun _ ->
          Error `Timeout );
      ]
    >|= function
    | Error e ->
        etcd_err (Fmt.str "TCP connection to etcd failed: %a" TCP.pp_error e)
    | Ok conn -> conn

  let connection_create_mtx = Lwt_mutex.create ()

  let create_connection ~stack =
    Lwt_mutex.with_lock connection_create_mtx (fun () ->
        match persistent_connection () with
        | Some x -> Lwt.return x
        | None ->
            Log.info (fun m -> m "connecting to etcd...");
            create_flow ~stack >>= fun flow ->
            Log.info (fun m -> m "TCP connection to etcd established");
            let shutdown_tcp () =
              Lwt.dont_wait
                (fun () -> TCP.close flow)
                (fun e ->
                  Log.err (fun m ->
                      m "closing TCP connection failed: %s"
                        (Printexc.to_string e)))
            in
            let h2_conn_error, h2_conn_error_resolver = Lwt.task () in
            let error_handler e =
              let msg = error_to_string e in
              (match e with
              | `Protocol_error (H2.Error_code.InternalError, s)
                when Stringext.find_from s ~pattern:"FLOW_EOF" != None ->
                  Log.err (fun m ->
                      m
                        "received HTTP/2 connection-level error: remote host \
                         closed connection")
              | _ ->
                  Log.err (fun m ->
                      m "received HTTP/2 connection-level error: %s" msg));
              shutdown_persistent_connection ();
              shutdown_tcp ();
              Lwt.wakeup_later h2_conn_error_resolver msg
            in
            let conn =
              let buffered_flow = Gluten_mirage.Buffered_flow.create flow in
              H2C.create_connection ~error_handler buffered_flow >>= fun conn ->
              H2C.ping conn >>= function
              | Error _ -> assert false
              | Ok () -> Lwt.return conn
            in
            Lwt.pick
              [
                conn;
                Lwt.protected h2_conn_error >>= etcd_err;
                ( timeout 5 "HTTP/2 connect timeout" >>= fun msg ->
                  shutdown_tcp ();
                  etcd_err msg );
              ]
            >>= fun conn ->
            Log.info (fun m -> m "HTTP/2 connection to etcd established");
            set_persistent_connection (conn, h2_conn_error);
            Lwt_list.iter_p (fun f -> f ()) !connection_established_callbacks
            >>= fun () -> Lwt.return (conn, h2_conn_error))

  let get_connection ~stack =
    (match persistent_connection () with
      | Some x -> Lwt.return x
      | _ -> create_connection ~stack)
    >|= fun (conn, conn_err) ->
    let conn_err' = Lwt.protected conn_err >>= etcd_err in
    (conn, conn_err')

  let next_req_id =
    let id = ref (-1) in
    fun () ->
      id := !id + 2;
      !id

  let make_unary_handler ~request ~decode =
   fun write_body read_body ->
    let read_body_with_timeout =
      Lwt.pick [ read_body; timeout 10 "gRPC request timeout" >>= etcd_err ]
    in
    let f s =
      Lwt.pick
        [ s >|= decode; timeout 120 "gRPC response timeout" >>= etcd_err ]
    in
    Grpc_lwt.Client.Rpc.unary ~f request write_body read_body_with_timeout

  let make_bidir_handler ~requests ~callback =
    let f writer reader =
      let rec send_queued_request () =
        Lwt_stream.get requests >>= function
        | None ->
            writer None;
            Lwt.return_unit
        | Some request ->
            writer (Some request);
            send_queued_request ()
      in
      let rec read_incoming_responses () =
        Lwt_stream.get reader >>= function
        | None -> Lwt.return_unit
        | Some response ->
            Lwt.async (fun () -> callback response);
            read_incoming_responses ()
      in
      Lwt.pick [ send_queued_request (); read_incoming_responses () ]
      >|= fun () -> Log.info (fun f -> f "bidir handler stopped")
    in
    Grpc_lwt.Client.Rpc.bidirectional_streaming ~f

  let do_grpc ~stack ~service ~rpc ~handler ~repr =
    get_connection ~stack >>= fun (conn, conn_err) ->
    let req_id = next_req_id () in
    Log.debug (fun m ->
        m "gRPC call [%d] service:(%s) rpc:(%s) req:(%s)" req_id service rpc
          repr);
    let stream_err, stream_err_resolver = Lwt.task () in
    let error_handler e =
      let msg = error_to_string e in
      Log.err (fun m ->
          m "gRPC call [%d] received HTTP/2 stream-level error: %s" req_id msg);
      Log.debug (fun m ->
          m "gRPC call [%d] service:(%s) rpc:(%s) req:(%s)" req_id service rpc
            repr);
      Lwt.wakeup_later_exn stream_err_resolver (Etcd_error msg)
    in
    let do_request = H2C.request conn ~error_handler in

    let grpc_resp =
      Grpc_lwt.Client.call ~service ~rpc ~scheme:"http" ~handler ~do_request ()
    in
    Lwt.pick [ grpc_resp; conn_err; stream_err ] >|= function
    | Error e -> etcd_err (Fmt.to_to_string H2.Status.pp_hum e)
    | Ok r -> r

  let rec do_grpc_unary ~stack ~service ~rpc ~request ~decode =
    let handler = make_unary_handler ~request ~decode in
    let repr = String.escaped request in
    do_grpc ~stack ~service ~rpc ~handler ~repr >>= function
    | Error e, _ -> etcd_err (Etcd_client.Result.show_error e)
    | Ok None, status -> (
        let open Grpc.Status in
        let code = code status in
        let message = message status in
        match code with
        | Unavailable ->
            Log.warn (fun f ->
                f
                  "request failed because service unavailable (%a), retrying \
                   in one second..."
                  Fmt.(option string)
                  message);
            Mirage_sleep.ns (Duration.of_sec 1) >>= fun () ->
            do_grpc_unary ~stack ~service ~rpc ~request ~decode
        | _ ->
            let err =
              Fmt.str "no response! status = (code: %a, msg: %a)" pp_code code
                Fmt.(option string)
                message
            in
            etcd_err err)
    | Ok (Some r), _ -> Lwt.return r

  let do_grpc_bidir ~stack ~service ~rpc ~callback =
    let requests, push_request = Lwt_stream.create () in
    let handler = make_bidir_handler ~requests ~callback in
    let repr = "bi-directional stream" in
    Lwt.async (fun () ->
        do_grpc ~stack ~service ~rpc ~handler ~repr >|= fun (_, status) ->
        Log.info (fun f ->
            f "bi-directional stream closed: %a" Grpc.Status.pp status));
    push_request

  let ( let* ) = Lwt.bind

  let update_revision (header : ResponseHeader.t option) =
    match header with
    | None -> ()
    | Some { revision; _ } -> last_known_revision := revision

  let txn stack ~(request : TxnRequest.t) : TxnResponse.t Lwt.t =
    let request = TxnRequest.to_proto request |> Etcd_client.Writer.contents in
    let decode = function
      | None -> Ok None
      | Some s ->
          Etcd_client.Reader.create s
          |> TxnResponse.from_proto |> Result.map Option.some
    in
    let* r =
      do_grpc_unary ~stack ~service:"etcdserverpb.KV" ~rpc:"Txn" ~request
        ~decode
    in
    update_revision r.header;
    Lwt.return r

  let put stack ~(request : PutRequest.t) : PutResponse.t Lwt.t =
    let request = PutRequest.to_proto request |> Etcd_client.Writer.contents in
    let decode = function
      | None -> Ok None
      | Some s ->
          Etcd_client.Reader.create s
          |> PutResponse.from_proto |> Result.map Option.some
    in
    let* r =
      do_grpc_unary ~stack ~service:"etcdserverpb.KV" ~rpc:"Put" ~request
        ~decode
    in
    update_revision r.header;
    Lwt.return r

  let range stack ~(request : RangeRequest.t) : RangeResponse.t Lwt.t =
    let request =
      RangeRequest.to_proto request |> Etcd_client.Writer.contents
    in
    let decode = function
      | None -> Ok None
      | Some s ->
          Etcd_client.Reader.create s
          |> RangeResponse.from_proto |> Result.map Option.some
    in
    let* r =
      do_grpc_unary ~stack ~service:"etcdserverpb.KV" ~rpc:"Range" ~request
        ~decode
    in
    update_revision r.header;
    Lwt.return r

  let delete_range stack ~(request : DeleteRangeRequest.t) :
      DeleteRangeResponse.t Lwt.t =
    let request =
      DeleteRangeRequest.to_proto request |> Etcd_client.Writer.contents
    in
    let decode = function
      | None -> Ok None
      | Some s ->
          Etcd_client.Reader.create s
          |> DeleteRangeResponse.from_proto |> Result.map Option.some
    in
    let* r =
      do_grpc_unary ~stack ~service:"etcdserverpb.KV" ~rpc:"DeleteRange"
        ~request ~decode
    in
    update_revision r.header;
    Lwt.return r

  let member_list stack ~(request : MemberListRequest.t) :
      MemberListResponse.t Lwt.t =
    let request =
      MemberListRequest.to_proto request |> Etcd_client.Writer.contents
    in
    let decode = function
      | None -> Ok None
      | Some s ->
          Etcd_client.Reader.create s
          |> MemberListResponse.from_proto |> Result.map Option.some
    in
    let* r =
      do_grpc_unary ~stack ~service:"etcdserverpb.Cluster" ~rpc:"MemberList"
        ~request ~decode
    in
    update_revision r.header;
    Lwt.return r

  let member_add stack ~(request : MemberAddRequest.t) :
      MemberAddResponse.t Lwt.t =
    let request =
      MemberAddRequest.to_proto request |> Etcd_client.Writer.contents
    in
    let decode = function
      | None -> Ok None
      | Some s ->
          Etcd_client.Reader.create s
          |> MemberAddResponse.from_proto |> Result.map Option.some
    in
    let* r =
      do_grpc_unary ~stack ~service:"etcdserverpb.Cluster" ~rpc:"MemberAdd"
        ~request ~decode
    in
    update_revision r.header;
    Lwt.return r

  let member_remove stack ~(request : MemberRemoveRequest.t) :
      MemberRemoveResponse.t Lwt.t =
    let request =
      MemberRemoveRequest.to_proto request |> Etcd_client.Writer.contents
    in
    let decode = function
      | None -> Ok None
      | Some s ->
          Etcd_client.Reader.create s
          |> MemberRemoveResponse.from_proto |> Result.map Option.some
    in
    let* r =
      do_grpc_unary ~stack ~service:"etcdserverpb.Cluster" ~rpc:"MemberRemove"
        ~request ~decode
    in
    update_revision r.header;
    Lwt.return r

  let member_update stack ~(request : MemberUpdateRequest.t) :
      MemberUpdateResponse.t Lwt.t =
    let request =
      MemberUpdateRequest.to_proto request |> Etcd_client.Writer.contents
    in
    let decode = function
      | None -> Ok None
      | Some s ->
          Etcd_client.Reader.create s
          |> MemberUpdateResponse.from_proto |> Result.map Option.some
    in
    let* r =
      do_grpc_unary ~stack ~service:"etcdserverpb.Cluster" ~rpc:"MemberUpdate"
        ~request ~decode
    in
    update_revision r.header;
    Lwt.return r

  let maintenance_status stack : StatusResponse.t Lwt.t =
    let request =
      StatusRequest.(make () |> to_proto) |> Etcd_client.Writer.contents
    in
    let decode = function
      | None -> Ok None
      | Some s ->
          Etcd_client.Reader.create s
          |> StatusResponse.from_proto |> Result.map Option.some
    in
    let* r =
      do_grpc_unary ~stack ~service:"etcdserverpb.Maintenance" ~rpc:"Status"
        ~request ~decode
    in
    update_revision r.header;
    Lwt.return r

  let is_future_rev (header : ResponseHeader.t option) =
    match header with
    | None ->
        Log.warn (fun f -> f "response has no header");
        true (* to be sure *)
    | Some { revision; _ } ->
        let is_future = Int64.compare revision !last_known_revision > 0 in
        if not is_future then
          Log.debug (fun f ->
              f "watch event ignored (rev %Ld <= %Ld)" revision
                !last_known_revision);
        (* do NOT update revision. other watchers may receive events for the
           same revision, and we don't want to reject them *)
        is_future

  module Watch = struct
    type callback = Event.t -> unit Lwt.t

    type t = {
      mutable write_request : string option -> unit;
          (** function obtained by establishing a connection, to push new
              requests to the long-lived connection *)
      callbacks : (int64, callback * WatchCreateRequest.t) Hashtbl.t;
          (** map from obtained watch id to maching callback (and initial
              request, if we need to recreate them) *)
      waiting_watch_id : (callback * WatchCreateRequest.t) Queue.t;
          (** when we send requests, remember the pending ones so we can match
              them with incoming "watcher created" events *)
    }

    let demux (callbacks, waiting_watch_id) (resp : WatchResponse.t) =
      let id = resp.watch_id in
      match Hashtbl.find_opt callbacks id with
      | Some _ when resp.canceled ->
          Log.info (fun f -> f "watch %Ld cancelled" id);
          Hashtbl.remove callbacks id;
          Lwt.return_unit
      | Some (callback, _) ->
          if resp.created then
            Log.warn (fun f -> f "watch %Ld created but already exists!" id);
          (* only forward events that we do not already know about *)
          if is_future_rev resp.header then
            List.map callback resp.events |> Lwt.join
          else Lwt.return_unit
      | None when resp.created -> (
          match Queue.take_opt waiting_watch_id with
          | None ->
              Log.err (fun f ->
                  f "watch %Ld created but we have no callback for it!" id);
              Lwt.return_unit
          | Some (callback, request) ->
              Log.info (fun f -> f "watch %Ld created" id);
              Hashtbl.add callbacks id (callback, request);
              update_revision resp.header;
              List.map callback resp.events |> Lwt.join)
      | None when resp.canceled ->
          Log.warn (fun f -> f "watch %Ld cancelled before created" id);
          Lwt.return_unit
      | None ->
          Log.err (fun f ->
              f "received watch %Ld event but we have no callback!" id);
          Lwt.return_unit

    let connect stack f =
      last_known_revision := 0L;
      let callback str =
        Etcd_client.Reader.create str
        |> WatchResponse.from_proto |> Result.map Option.some
        |> function
        | Error e -> etcd_err (Etcd_client.Result.show_error e)
        | Ok None -> etcd_err "no response!"
        | Ok (Some r) -> f r
      in
      let write_request =
        do_grpc_bidir ~stack ~service:"etcdserverpb.Watch" ~rpc:"Watch"
          ~callback
      in
      write_request

    let cancel t ~(request : WatchCancelRequest.t) =
      let id = request in
      let request =
        WatchRequest.make ~request_union:(`Cancel_request request) ()
      in
      let request =
        WatchRequest.to_proto request |> Etcd_client.Writer.contents
      in
      Log.info (fun f -> f "request to cancel watch %Ld sent" id);
      t.write_request (Some request)

    let clear_all t =
      Hashtbl.iter
        (fun watch_id _ ->
          let request = WatchCancelRequest.make ~watch_id () in
          cancel t ~request)
        t.callbacks;
      Hashtbl.clear t.callbacks;
      Queue.clear t.waiting_watch_id

    let init stack =
      let callbacks = Hashtbl.create 10 in
      let waiting_watch_id = Queue.create () in
      let f = demux (callbacks, waiting_watch_id) in
      let write_request = connect stack f in
      Log.info (fun f -> f "initial watch stream started");
      { write_request; callbacks; waiting_watch_id }

    let create t ~(request : WatchCreateRequest.t) ~(callback : callback) =
      let request' =
        WatchRequest.make ~request_union:(`Create_request request) ()
      in
      let request' =
        WatchRequest.to_proto request' |> Etcd_client.Writer.contents
      in
      Queue.add (callback, request) t.waiting_watch_id;
      Log.info (fun f -> f "new watch request sent");
      t.write_request (Some request')

    let reconnect t stack =
      let f = demux (t.callbacks, t.waiting_watch_id) in
      let pending = Queue.to_seq t.waiting_watch_id |> List.of_seq in
      Queue.clear t.waiting_watch_id;
      let active = Hashtbl.to_seq_values t.callbacks |> List.of_seq in
      Hashtbl.clear t.callbacks;
      let to_replay = pending @ active in
      t.write_request <- connect stack f;
      Log.info (fun f ->
          f "watch stream restarted. replaying %d watchers..."
            (List.length to_replay));
      List.iter
        (fun (callback, request) -> create t ~request ~callback)
        to_replay
  end

  (* let compact ~ctx ~req =
     let uri = Request.build_uri "/v3/kv/compaction" in
     let body =
       Request.write_as_json_body Etcdserverpb_compaction_request.to_yojson req
     in
     C.call ~ctx `POST uri ~headers ~body >>= fun (resp, body) ->
     Request.read_json_body_as
       (JsonSupport.unwrap Etcdserverpb_compaction_response.of_yojson)
       resp body *)
end

module KV_RO (Stack : Tcpip.Stack.V4V6) = struct
  module Key = Mirage_kv.Key
  module Etcd = Etcd_api (Stack)

  module Txn_batcher = struct
    type t = {
      max_txn_size : int;
      mutable txns : TxnRequest.t list;
      mutable ops_buffer : RequestOp.t list;
      mutable cur_buf_size : int;
    }

    let create ?(max_txn_size = 512) () =
      { max_txn_size; txns = []; ops_buffer = []; cur_buf_size = 0 }

    let flush_buffer t =
      let req = TxnRequest.make ~success:t.ops_buffer () in
      t.txns <- req :: t.txns;
      t.ops_buffer <- [];
      t.cur_buf_size <- 0

    let add_op t op =
      let op = RequestOp.make ~request:op () in
      t.ops_buffer <- op :: t.ops_buffer;
      t.cur_buf_size <- t.cur_buf_size + 1;
      if t.cur_buf_size >= t.max_txn_size then flush_buffer t;
      Lwt_result.return ()

    let finalize t stack =
      if t.cur_buf_size > 0 then flush_buffer t;
      let counter = ref 0 in
      let promises =
        Lwt_list.map_s
          (fun request ->
            Etcd.txn stack ~request >>= fun r ->
            counter := !counter + t.max_txn_size;
            Log.debug (fun f -> f "batch: applied %d ops" !counter);
            Lwt.return r)
          t.txns
      in
      t.txns <- [];
      promises
  end

  type t = {
    stack : Stack.t;
    mode : [ `Normal | `Batch of Txn_batcher.t ];
    member_id : int64;
    watcher : Etcd.Watch.t;
  }

  type key = Key.t

  let etcd_try f =
    Lwt.catch
      (fun () -> f ())
      (fun e ->
        let msg =
          match e with Etcd_error s -> s | exn -> Printexc.to_string exn
        in
        Log.debug (fun m ->
            let bt = Printexc.get_backtrace () in
            m "%s backtrace:\n%s" msg bt);
        Lwt.return (Error (`Etcd_error msg)))

  let bytes_of_key k = Bytes.of_string (Key.to_string k)
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
        match resp.RangeResponse.kvs with
        | { KeyValue.mod_revision = i; _ } :: _ -> Ok (Ptime.v (0, i))
        | _ -> Error (`Not_found k))

  (** WARNING: only works on Values, will return None for dictionaries *)
  let exists t k =
    let key = bytes_of_key k in
    let request = RangeRequest.make ~key ~count_only:true () in
    etcd_try (fun () ->
        Etcd.range t.stack ~request >|= fun resp ->
        if Int64.compare resp.RangeResponse.count 0L > 0 then Ok (Some `Value)
        else Ok None)

  let get t k =
    let key = bytes_of_key k in
    let request = RangeRequest.make ~key () in
    etcd_try (fun () ->
        Etcd.range t.stack ~request >|= fun resp ->
        match resp.RangeResponse.kvs with
        | { KeyValue.value = s; _ } :: _ -> Ok (Bytes.to_string s)
        | _ -> Error (`Not_found k))

  let etcd_range_of_range range =
    let open Keyfender.Kv_ext in
    let dir k =
      Bytes.of_string (match Key.to_string k with "/" -> "/" | s -> s ^ "/")
    in
    let key =
      match Range.first_key range with
      | None -> Range.prefix range |> dir
      | Some first_key -> Key.to_string first_key |> Bytes.of_string
    in
    let range_end =
      match Range.range_end range with
      | None -> Range.range_end_of_prefix (Range.prefix range |> dir)
      | Some range_end -> Key.to_string range_end |> Bytes.of_string
    in
    (key, range_end)

  let pp_event fmt (event : Keyfender.Kv_ext.event) =
    let kind = match event.kind with `Put -> "PUT" | `Delete -> "DELETE" in
    Fmt.pf fmt "(%s %a)" kind Mirage_kv.Key.pp event.key

  let create_watch t (range : Keyfender.Kv_ext.Range.t) callback =
    let key, range_end = etcd_range_of_range range in
    let request =
      WatchCreateRequest.make ~key ~range_end ~progress_notify:true ()
    in
    let callback (event : Event.t) =
      match event.kv with
      | None ->
          Log.warn (fun f -> f "received watch event with no KV field");
          Lwt.return_unit
      | Some kv ->
          let key = Mirage_kv.Key.v (String.of_bytes kv.key) in
          let kind = match event.type' with DELETE -> `Delete | PUT -> `Put in
          let event' = Keyfender.Kv_ext.{ kind; key } in
          Log.debug (fun f -> f "processing remote event %a" pp_event event');
          callback event'
    in
    Etcd.Watch.create t.watcher ~request ~callback

  let clear_watches t = Etcd.Watch.clear_all t.watcher

  (* remove *consecutive* duplicates in a list*)
  let rec dedup = function
    | [] -> []
    | [ x ] -> [ x ]
    | a :: b :: tl when a = b -> dedup (b :: tl)
    | a :: b :: tl -> a :: dedup (b :: tl)

  let list_range t range =
    let key, range_end = etcd_range_of_range range in
    let request =
      RangeRequest.(
        make ~key ~range_end ~keys_only:true ~sort_order:SortOrder.DESCEND ())
    in
    etcd_try (fun () ->
        Etcd.range t.stack ~request >|= fun resp ->
        let rec acc_keys acc kvs =
          match kvs with
          | [] -> acc
          | { KeyValue.key = k; _ } :: t ->
              let key = Bytes.to_string k in
              let res = (Mirage_kv.Key.v key, `Value) in
              (acc_keys [@tailcall]) (res :: acc) t
        in
        (* remove duplicates in *already sorted* list *)
        let keys = acc_keys [] resp.RangeResponse.kvs |> dedup in
        Ok keys)

  let list t key = list_range t (Keyfender.Kv_ext.Range.create ~prefix:key ())

  let digest t k =
    let open Lwt_result.Infix in
    get t k >|= fun v -> Digestif.SHA256.(to_hex (digest_string v))

  module Cluster = struct
    type member = { id : int64; name : string; urls : string list }
    type cluster_error = [ `Cluster_error of string ]

    let cluster_member_of_member (t : Member.t) =
      { id = t.iD; name = t.name; urls = t.peerURLs }

    let etcd_try f =
      etcd_try f
      >|= Result.map_error (function `Etcd_error s -> `Cluster_error s)

    let my_id t = t.member_id

    let member_list t =
      let request = MemberListRequest.make () in
      etcd_try (fun () ->
          Etcd.member_list t.stack ~request >|= fun resp ->
          Ok (List.map cluster_member_of_member resp.MemberListResponse.members))

    let member_remove ~id t =
      let request = MemberRemoveRequest.make ~iD:id () in
      etcd_try (fun () ->
          Etcd.member_remove t.stack ~request >|= fun resp ->
          Ok
            (List.map cluster_member_of_member resp.MemberRemoveResponse.members))

    let member_update ~id ~urls t =
      let request = MemberUpdateRequest.make ~iD:id ~peerURLs:urls () in
      etcd_try (fun () ->
          Etcd.member_update t.stack ~request >|= fun resp ->
          Ok
            (List.map cluster_member_of_member resp.MemberUpdateResponse.members))

    let member_add ~urls t =
      let request = MemberAddRequest.make ~peerURLs:urls () in
      etcd_try (fun () ->
          Etcd.member_add t.stack ~request >|= fun resp ->
          Ok (List.map cluster_member_of_member resp.MemberAddResponse.members))
  end

  let status stack =
    etcd_try (fun () ->
        Etcd.maintenance_status stack >|= fun resp ->
        let leader = resp.leader in
        let db_size = resp.dbSize in
        let errors = resp.errors in
        match resp.header with
        | None -> Error (`Etcd_error "response did not have a header")
        | Some header ->
            Log.info (fun f ->
                f "status: (id=%Lx,@,leader=%Lx,@,db_size=%Ld,@,errors=[%a])"
                  header.member_id leader db_size
                  Fmt.(list string)
                  errors);
            Ok header.member_id)

  let connect stack =
    status stack >|= function
    | Error e -> Error e
    | Ok member_id ->
        let watcher = Etcd.Watch.init stack in
        let t = { stack; mode = `Normal; member_id; watcher } in
        let restart_watcher () =
          Etcd.Watch.reconnect watcher stack;
          Lwt.return_unit
        in
        Etcd.connection_established_callbacks :=
          restart_watcher :: !Etcd.connection_established_callbacks;
        Ok t
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
    match t.mode with
    | `Normal ->
        etcd_try (fun () -> Etcd.put t.stack ~request >|= fun _resp -> Ok ())
    | `Batch b -> Txn_batcher.add_op b (`Request_put request)

  let remove t k =
    (* We don't know if the key is meant to refer to a dictionary or a single
       entry in the Mirage abstraction. We could check by making a (potentially
       costly) request to the store, to see if keys of the form "KEY/..." exist.

       Rather, we always handle both cases, since they are mutually exclusive:
           - single entry: delete exactly the key "KEY"
           - dictionary: delete the range ["KEY/"; "KEY0"[
    *)
    let key_single = bytes_of_key k in
    let exec_req ~request =
      match t.mode with
      | `Normal ->
          etcd_try (fun () ->
              Etcd.delete_range t.stack ~request >|= fun _ -> Ok ())
      | `Batch b -> Txn_batcher.add_op b (`Request_delete_range request)
    in
    let request_single = DeleteRangeRequest.make ~key:key_single () in
    Lwt_result.bind (exec_req ~request:request_single) @@ fun () ->
    let key_dic = Mirage_kv.Key.to_string k ^ "/" |> Bytes.of_string in
    let range_end = Keyfender.Kv_ext.Range.range_end_of_prefix key_dic in
    let request_dic = DeleteRangeRequest.make ~key:key_dic ~range_end () in
    exec_req ~request:request_dic

  let batch t ?retries:(_ = 42) f =
    let batcher = Txn_batcher.create () in
    f { t with mode = `Batch batcher } >>= fun value ->
    etcd_try (fun () ->
        Txn_batcher.finalize batcher t.stack >|= fun _resp -> Ok ())
    >|= fun res ->
    match res with
    | Ok () -> value
    | Error (`Etcd_error msg) -> raise (Etcd_error msg)
    | Error _ -> raise (Etcd_error "unknown error")
end

let etcd_peer_port = 2380

module Peer_relay
    (X : Tcpip.Tcp.S with type ipaddr = Ipaddr.t)
    (Y : Tcpip.Tcp.S with type ipaddr = Ipaddr.t) =
struct
  let relay_bidir (y_tcp : Y.t) (xf : X.flow) target =
    (* TODO error management *)
    let src, _ = X.dst xf in
    Y.create_connection y_tcp (target, etcd_peer_port) >>= function
    | Error e ->
        Log.err (fun f ->
            f "relay: cannot reach target of (%a -> %a): %a" Ipaddr.pp src
              Ipaddr.pp target Y.pp_error e);
        Lwt.return_unit
    | Ok yf ->
        Log.debug (fun f ->
            f "relay: new session: %a -> %a" Ipaddr.pp src Ipaddr.pp target);
        let close_all () = X.close xf >>= fun () -> Y.close yf in
        let relay_unidir (type f1) (type f2)
            (module A : Tcpip.Tcp.S with type flow = f1)
            (module B : Tcpip.Tcp.S with type flow = f2) (af : f1) (bf : f2) =
          let rec aux () =
            A.read af >>= function
            | Ok `Eof -> close_all ()
            | Error _ -> close_all ()
            | Ok (`Data b) -> (
                B.write bf b >>= function
                | Ok () -> aux ()
                | Error _ -> close_all ())
          in
          aux ()
        in
        Lwt.pick
          [
            relay_unidir (module X) (module Y) xf yf;
            relay_unidir (module Y) (module X) yf xf;
          ]
        >>= fun () ->
        Log.debug (fun f ->
            f "relay: end of session: %a -> %a" Ipaddr.pp src Ipaddr.pp target);
        Lwt.return_unit

  let listen x y target =
    X.listen x ~port:etcd_peer_port (fun flow ->
        let target =
          match target with Some target -> target | None -> X.src flow |> fst
        in
        relay_bidir y flow target);
    Lwt.return_unit
end
