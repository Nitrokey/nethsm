(* Copyright 2023 - 2023, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

open Lwt.Infix

module Make (Wm : Webmachine.S with type +'a io = 'a Lwt.t) (Hsm : Hsm.S) =
struct
  module Access = Access.Make (Wm) (Hsm)

  type body = Cohttp_lwt.Body.t

  let respond_error_raw (code, msg) rd =
    let cc hdr = Cohttp.Header.replace hdr "content-type" "application/json" in
    let rd' = Webmachine.Rd.with_resp_headers cc rd in
    Wm.respond ~body:(`String (Json.error msg)) code rd'

  let respond_error (e, msg) rd =
    let code = Hsm.error_to_code e in
    respond_error_raw (code, msg) rd

  let respond_status (e, msg) rd =
    let code = Cohttp.Code.code_of_status e in
    respond_error_raw (code, msg) rd

  let err_to_bad_request ok rd = function
    | Error m -> respond_error (Bad_request, m) rd
    | Ok data -> ok data

  let is_glob id = String.ends_with ~suffix:"*" id

  let lookup_path_info ?(allow_glob = false) ok key rd =
    err_to_bad_request ok rd
      (match Webmachine.Rd.lookup_path_info key rd with
      | None -> Error "no ID provided"
      | Some x ->
          let id =
            if allow_glob && is_glob x then String.sub x 0 (String.length x - 1)
            else x
          in
          Result.map (fun _ -> x) (Json.valid_id id))

  let lookup_path_nid ok rd =
    err_to_bad_request ok rd
      (match Webmachine.Rd.lookup_path_info "id" rd with
      | None -> Error "no ID provided"
      | Some x -> Hsm.Nid.of_string x)

  let date () =
    let ptime_to_http_date ptime =
      let (y, m, d), ((hh, mm, ss), _) = Ptime.to_date_time ptime
      and weekday =
        match Ptime.weekday ptime with
        | `Mon -> "Mon"
        | `Tue -> "Tue"
        | `Wed -> "Wed"
        | `Thu -> "Thu"
        | `Fri -> "Fri"
        | `Sat -> "Sat"
        | `Sun -> "Sun"
      and month =
        [|
          "Jan";
          "Feb";
          "Mar";
          "Apr";
          "May";
          "Jun";
          "Jul";
          "Aug";
          "Sep";
          "Oct";
          "Nov";
          "Dec";
        |]
      in
      Printf.sprintf "%s, %02d %s %04d %02d:%02d:%02d GMT" weekday d
        (Array.get month (m - 1))
        y hh mm ss
    in
    ptime_to_http_date (Hsm.now ())

  let get_namespace rd =
    let user_nid = Access.get_user rd.Webmachine.Rd.req_headers in
    user_nid.namespace

  class virtual base =
    object
      inherit [body] Wm.resource

      method! uri_too_long : (bool, body) Wm.op =
        fun rd ->
          Wm.continue
            (String.length (Uri.to_string rd.Webmachine.Rd.uri) > 2000)
            rd

      method! finish_request : (unit, body) Wm.op =
        fun rd ->
          let cc hdr = Cohttp.Header.replace hdr "Date" (date ()) in
          let rd' = Webmachine.Rd.with_resp_headers cc rd in
          Wm.continue () rd'
    end

  class virtual base_with_body_length =
    object
      inherit base

      (* limit body to 1MB *)
      val max_body_length = 1024 * 1024

      method! valid_entity_length : (bool, body) Wm.op =
        fun rd ->
          match
            Cohttp.Header.get rd.Webmachine.Rd.req_headers "content-length"
          with
          | None -> (* chunked encoding? *) Wm.continue true rd
          | Some len -> (
              try
                let int_len = int_of_string len in
                Wm.continue (int_len <= max_body_length) rd
              with Failure _ -> Wm.continue false rd)
    end

  class virtual base_with_large_body_length =
    object
      inherit base_with_body_length

      (* raise body limit to 67MB, base64 of 50MB *)
      val! max_body_length = 1024 * 1024 * 67
    end

  class no_cache =
    object
      method finish_request : (unit, body) Wm.op =
        fun rd ->
          let cc hdr =
            let hdr' = Cohttp.Header.replace hdr "Cache-control" "no-cache" in
            Cohttp.Header.replace hdr' "Date" (date ())
          in
          let rd' = Webmachine.Rd.with_resp_headers cc rd in
          Wm.continue () rd'
    end

  class role hsm_state role ip =
    object
      method is_authorized : (Wm.auth, body) Wm.op =
        Access.is_authorized hsm_state ip

      method forbidden : (bool, body) Wm.op =
        fun rd ->
          Access.forbidden hsm_state role rd >>= fun auth -> Wm.continue auth rd
    end

  class role_operator_get hsm_state ip =
    object
      method is_authorized : (Wm.auth, body) Wm.op =
        Access.is_authorized hsm_state ip

      method forbidden : (bool, body) Wm.op =
        fun rd ->
          Access.forbidden hsm_state `Administrator rd >>= function
          | true when rd.meth = `GET ->
              (* no admin - only get allowed for operator *)
              Access.forbidden hsm_state `Operator rd >>= fun not_an_operator ->
              Wm.continue not_an_operator rd
          | not_an_admin -> Wm.continue not_an_admin rd
    end

  (** By default, enforce on all HTTP methods *)
  class no_namespace ?exclude_meths () =
    object
      method forbidden : (bool, body) Wm.op =
        fun rd ->
          match exclude_meths with
          | Some methods when List.mem rd.meth methods -> Wm.continue false rd
          | _ ->
              let user = Access.get_user rd.Webmachine.Rd.req_headers in
              let is_root = user.namespace = None in
              Wm.continue (not is_root) rd
    end

  let ( >>=? ) m f =
    let open Wm in
    m >>= function
    | Ok x, rd -> f x rd
    | Error code, rd -> Lwt.return (Error code, rd)

  let join_ops ~join fs rd =
    let rec aux rd = function
      | [] -> assert false
      | [ f ] -> f rd
      | f :: tl ->
          aux rd tl >>=? fun x rd ->
          f rd >>=? fun y rd -> Wm.continue (join x y) rd
    in
    aux rd fs

  (*  R-Role ([no_namespace] + [role])
      User is Root (no namespace) and has given role *)
  class r_role ?r_exclude_meths hsm_state role ip =
    object
      inherit role hsm_state role ip as role
      inherit! no_namespace ?exclude_meths:r_exclude_meths () as namespace

      method! forbidden =
        join_ops ~join:( || ) [ role#forbidden; namespace#forbidden ]
    end

  (*  For endpoints managing users, ensure that the target and caller are
      strictly in the same namespace.
      - this is a strict check: if the caller is a R-User and target a N-User,
        the check will fail, despite the higher privileges of the caller
      - the check is *relaxed* (i.e. the above situation would pass) if either:
        - the target's namespace has not been created yet (since no member of that
          namespace could be the caller anyway)
        - the HTTP method is explicitly given in [root_allowed_for]
      - the check is completely disabled in the HTTP method is explicitly given
        in exclude_meths *)
  class target_same_namespace ?(root_allowed_for = []) ?exclude_meths hsm_state
    =
    object
      method forbidden : (bool, body) Wm.op =
        fun rd ->
          match exclude_meths with
          | Some methods when List.mem rd.meth methods -> Wm.continue false rd
          | _ ->
              let user = Access.get_user rd.Webmachine.Rd.req_headers in
              let caller_namespace = user.namespace in
              let filter_error f = function
                | Ok x -> f x
                | Error e -> respond_error e rd
              in
              let strict_applies = not (List.mem rd.meth root_allowed_for) in
              lookup_path_nid
                (fun nid ->
                  let user_namespace = nid.namespace in
                  Hsm.Namespace.exists hsm_state user_namespace
                  >>= filter_error @@ fun user_namespace_exists ->
                      (* If caller is root and namespace does not exist
                         (or root allowed), then grant access and stop
                      *)
                      let strict = strict_applies && user_namespace_exists in
                      if caller_namespace = None && not strict then
                        Wm.continue false rd
                      else
                        (* Otherwise, actually check that caller is in
                           user namespace *)
                        let same_namespace =
                          caller_namespace = user_namespace
                        in
                        Wm.continue (not same_namespace) rd)
                rd
    end

  class role_operator_get_self hsm_state ip =
    object
      method is_authorized : (Wm.auth, body) Wm.op =
        Access.is_authorized hsm_state ip

      method forbidden : (bool, body) Wm.op =
        fun rd ->
          Access.forbidden hsm_state `Administrator rd >>= function
          | true when rd.meth = `GET ->
              (* no admin - only get allowed for operator on self *)
              Access.forbidden hsm_state `Operator rd >>= fun not_an_operator ->
              if not_an_operator then Wm.continue not_an_operator rd
              else
                let user = Access.get_user rd.Webmachine.Rd.req_headers in
                lookup_path_nid (fun nid -> Wm.continue (nid <> user) rd) rd
          | not_an_admin -> Wm.continue not_an_admin rd
    end

  class input_state_validated hsm_state allowed_input_states =
    object
      method service_available : (bool, body) Wm.op =
        if List.exists (Access.is_in_state hsm_state) allowed_input_states then
          Wm.continue true
        else respond_error (Precondition_failed, "Service not available")
    end

  class virtual get_json =
    object (self)
      method virtual private to_json : body Wm.provider

      method content_types_provided :
          ((string * body Wm.provider) list, body) Wm.op =
        Wm.continue [ ("application/json", self#to_json) ]

      method content_types_accepted :
          ((string * body Wm.acceptor) list, body) Wm.op =
        Wm.continue []
    end

  class virtual put_json =
    object (self)
      method virtual private of_json : Yojson.Safe.t -> body Wm.acceptor

      method content_types_accepted :
          ((string * body Wm.acceptor) list, body) Wm.op =
        Wm.continue [ ("application/json", self#parse_json) ]

      method content_types_provided :
          ((string * body Wm.provider) list, body) Wm.op =
        Wm.continue [ ("application/json", Wm.continue `Empty) ]

      method private parse_json rd =
        let body = rd.Webmachine.Rd.req_body in
        Cohttp_lwt.Body.to_string body >>= fun content ->
        try self#of_json (Yojson.Safe.from_string content) rd
        with Yojson.Json_error msg ->
          respond_error
            (Hsm.Bad_request, Printf.sprintf "Invalid JSON: %s." msg)
            rd

      method allowed_methods : (Cohttp.Code.meth list, body) Wm.op =
        Wm.continue [ `PUT ]
    end

  class virtual post =
    object (self)
      method virtual process_post : (bool, body) Wm.op

      method content_types_accepted :
          ((string * body Wm.acceptor) list, body) Wm.op =
        Wm.continue [ ("application/json", self#process_post) ]

      method content_types_provided :
          ((string * body Wm.provider) list, body) Wm.op =
        Wm.continue [ ("application/json", Wm.continue `Empty) ]

      method allowed_methods : (Cohttp.Code.meth list, body) Wm.op =
        Wm.continue [ `POST ]
    end

  class virtual post_json =
    object (self)
      inherit post
      method virtual private of_json : Yojson.Safe.t -> body Wm.acceptor

      method private parse_json rd =
        let body = rd.Webmachine.Rd.req_body in
        Cohttp_lwt.Body.to_string body >>= fun content ->
        try self#of_json (Yojson.Safe.from_string content) rd
        with Yojson.Json_error msg ->
          respond_error
            (Hsm.Bad_request, Printf.sprintf "Invalid JSON: %s." msg)
            rd

      method process_post = self#parse_json
    end
end
