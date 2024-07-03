(* Copyright 2023 - 2023, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

open Lwt.Infix

module Make (Wm : Webmachine.S with type +'a io = 'a Lwt.t) (Hsm : Hsm.S) =
struct
  module Access = Access.Make (Wm) (Hsm)
  module Endpoint = Endpoint.Make (Wm) (Hsm)

  let can_create_user hsm_state rd ~caller_nid ~target_nid ok req =
    let open Hsm.Nid in
    if caller_nid.namespace = target_nid.namespace then
      (* Same namespace: OK *)
      ok target_nid req
    else if Option.is_some caller_nid.namespace then
      (* Different namespace and caller is N-User: KO *)
      Endpoint.respond_error
        (Hsm.Forbidden, "N-User trying to create user for another namespace")
        rd
    else
      Hsm.Namespace.exists hsm_state target_nid.namespace >>= function
      | Error e -> Endpoint.respond_error e rd
      | Ok true ->
          (* R-User creating N-User when N exists: KO *)
          Endpoint.respond_error
            ( Hsm.Forbidden,
              "R-User trying to create N-User for an already created namespace"
            )
            rd
      | Ok false ->
          (* R-User creating N-User when N doesn't exist: OK *)
          ok target_nid req

  class handler_users hsm_state ip =
    object (self)
      inherit Endpoint.base_with_body_length
      inherit! Endpoint.input_state_validated hsm_state [ `Operational ]
      inherit! Endpoint.role hsm_state `Administrator ip
      val mutable new_id = None

      method private get_json rd =
        (* Return only users in the same namespace *)
        let namespace = Endpoint.get_namespace rd in
        Hsm.User.list ~namespace hsm_state >>= function
        | Error e -> Endpoint.respond_error e rd
        | Ok users ->
            let items =
              List.map (fun user -> `Assoc [ ("user", `String user) ]) users
            in
            let body = Yojson.Safe.to_string (`List items) in
            Wm.continue (`String body) rd

      method private set_json rd =
        let body = rd.Webmachine.Rd.req_body in
        Cohttp_lwt.Body.to_string body >>= fun content ->
        let ok nid (user : Json.user_req) =
          Hsm.User.add hsm_state nid ~role:user.role ~name:user.realName
            ~passphrase:user.passphrase
          >>= function
          | Ok () ->
              let str = Hsm.Nid.to_string nid in
              let body =
                `Assoc [ ("id", `String str) ] |> Yojson.Basic.to_string
              in
              let rd = { rd with resp_body = `String body } in
              Wm.continue true rd
          | Error e -> Endpoint.respond_error e rd
        in
        let ok (req : Json.user_req) =
          (* must succeed since we set it ourselves, and webmachine ensures that
             it already happened. *)
          let target_nid = Option.get new_id in
          let caller_nid = Access.get_user rd.Webmachine.Rd.req_headers in
          can_create_user hsm_state rd ~caller_nid ~target_nid ok req
        in
        Json.decode_user_req content |> Endpoint.err_to_bad_request ok rd

      method! post_is_create rd = Wm.continue true rd

      method! create_path rd =
        let id = Hsm.generate_id () in
        (* Create user in caller's namespace *)
        let namespace = Endpoint.get_namespace rd in
        let nid = { Hsm.Nid.namespace; id } in
        new_id <- Some nid;
        let path = Hsm.Nid.to_string nid in
        Wm.continue path rd

      method! allowed_methods rd = Wm.continue [ `POST; `GET ] rd

      method content_types_provided rd =
        Wm.continue [ ("application/json", self#get_json) ] rd

      method content_types_accepted rd =
        Wm.continue [ ("application/json", self#set_json) ] rd

      method! generate_etag rd =
        Hsm.User.list_digest hsm_state >>= fun digest -> Wm.continue digest rd
    end

  class handler hsm_state ip =
    object (self)
      inherit Endpoint.base_with_body_length
      inherit! Endpoint.input_state_validated hsm_state [ `Operational ]
      inherit! Endpoint.role_operator_get_self hsm_state ip as role

      inherit!
        Endpoint.target_same_namespace
          ~root_allowed_for:[ `GET ] ~exclude_meths:[ `PUT; `POST ] hsm_state as namespace
      (* Same namespace check is not applicable for PUT, where the referred user
         does not exist yet. For GET, R-Users can still access N-Users info *)

      val mutable new_id = None

      method! forbidden =
        (* Check both role and namespace *)
        Endpoint.join_ops ~join:( || ) [ role#forbidden; namespace#forbidden ]

      method private get_json rd =
        let ok nid =
          Hsm.User.get hsm_state nid >>= function
          | Error e -> Endpoint.respond_error e rd
          | Ok info ->
              let module Info = Hsm.User.Info in
              let user =
                { Json.realName = Info.name info; role = Info.role info }
              in
              let body = Yojson.Safe.to_string (Json.user_res_to_yojson user) in
              Wm.continue (`String body) rd
        in
        Endpoint.lookup_path_nid ok rd

      method private set_json rd =
        let body = rd.Webmachine.Rd.req_body in
        Cohttp_lwt.Body.to_string body >>= fun content ->
        let ok nid (user : Json.user_req) =
          Hsm.User.add hsm_state nid ~role:user.role ~name:user.realName
            ~passphrase:user.passphrase
          >>= function
          | Ok _id ->
              let rd =
                if rd.Webmachine.Rd.meth = `POST then
                  let str = Hsm.Nid.to_string nid in
                  let body =
                    `Assoc [ ("id", `String str) ] |> Yojson.Basic.to_string
                  in
                  { rd with resp_body = `String body }
                else
                  let cc hdr =
                    Cohttp.Header.replace hdr "Location" (Uri.path rd.uri)
                  in
                  Webmachine.Rd.with_resp_headers cc rd
              in
              Wm.continue true rd
          | Error e -> Endpoint.respond_error e rd
        in
        let ok nid (req : Json.user_req) =
          let caller_nid = Access.get_user rd.Webmachine.Rd.req_headers in
          can_create_user hsm_state rd ~caller_nid ~target_nid:nid ok req
        in
        let ok nid =
          Endpoint.err_to_bad_request (ok nid) rd (Json.decode_user_req content)
        in
        match rd.Webmachine.Rd.meth with
        | `PUT -> Endpoint.lookup_path_nid ok rd
        | `POST -> ok (Option.get new_id)
        | _ -> assert false

      method! resource_exists rd =
        let ok nid =
          Hsm.User.exists hsm_state nid >>= function
          | Ok does_exist -> Wm.continue does_exist rd
          | Error e -> Endpoint.respond_error e rd
        in
        match rd.Webmachine.Rd.meth with
        | `POST -> Wm.continue true rd
        | _ -> Endpoint.lookup_path_nid ok rd

      method! post_is_create rd = Wm.continue true rd

      method! create_path rd =
        let error () =
          Endpoint.respond_error
            ( Hsm.Bad_request,
              "POST on this endpoint expects a prefix of the form '/ns~' to \
               select in which namespace the new user should be created. For a \
               new root user, don't add a trailing '/'." )
            rd
        in
        match Webmachine.Rd.lookup_path_info "id" rd with
        | None -> error ()
        | Some x -> (
            match Hsm.Nid.unsafe_of_string x with
            | { namespace = Some n; id = "" } when n <> "" ->
                let id = Hsm.generate_id () in
                let nid = { Hsm.Nid.namespace = Some n; id } in
                new_id <- Some nid;
                let path = Hsm.Nid.to_string nid in
                (* Our URI looks like .../users/namespace1~
                   Webmachine appends the created ressource path (with a /) to
                   that URI at this step.
                   To avoid having a resulting URI that
                   looks like .../users/namespace1~/namespace1~abcdef1234
                   we have to remove the last segment from our current URI *)
                let uri =
                  let segments = Uri.path rd.uri |> String.split_on_char '/' in
                  let rec without_last acc = function
                    | [] -> assert false
                    | [ _ ] -> acc
                    | x :: tl when x = "" -> without_last acc tl
                    | x :: tl -> without_last (acc ^ "/" ^ x) tl
                  in
                  Uri.with_path rd.uri (without_last "" segments)
                in
                Wm.continue path { rd with uri }
            | _ -> error ())

      method! allowed_methods rd = Wm.continue [ `PUT; `GET; `DELETE; `POST ] rd

      method content_types_provided rd =
        Wm.continue [ ("application/json", self#get_json) ] rd

      method content_types_accepted rd =
        Wm.continue [ ("application/json", self#set_json) ] rd

      method! delete_resource rd =
        let ok nid =
          if Access.get_user rd.Webmachine.Rd.req_headers = nid then
            Endpoint.respond_error
              (Bad_request, "Users cannot delete themselves")
              rd
          else
            Hsm.User.remove hsm_state nid >>= function
            | Ok () -> Wm.continue true rd
            | Error e -> Endpoint.respond_error e rd
        in
        Endpoint.lookup_path_nid ok rd

      method! generate_etag rd =
        Endpoint.lookup_path_nid
          (fun nid ->
            Hsm.User.digest hsm_state nid >>= fun digest ->
            Wm.continue digest rd)
          rd
    end

  (* Forbidden conditions applicable for passphrase and tags.
     This is regardless of namespace conditions, which are checked elsewhere.
     Access is granted if either:
         - caller is an admin
         - caller targetting itself, and is an operator
  *)
  let forbidden_admin_or_self_operator hsm_state rd =
    Access.forbidden hsm_state `Administrator rd >>= fun not_an_admin ->
    let not_an_operator nid =
      if Access.get_user rd.Webmachine.Rd.req_headers = nid then
        Access.forbidden hsm_state `Operator rd
      else Lwt.return not_an_admin
    in
    Endpoint.lookup_path_nid
      (fun nid -> not_an_operator nid >>= fun x -> Wm.continue x rd)
      rd
    >>= function
    | Error _, _ -> Wm.continue true rd
    | Ok not_an_operator, _ -> Wm.continue (not_an_admin && not_an_operator) rd

  class handler_passphrase hsm_state ip =
    object
      inherit Endpoint.base_with_body_length
      inherit! Endpoint.input_state_validated hsm_state [ `Operational ]
      inherit! Endpoint.post_json
      inherit! Endpoint.no_cache
      inherit! Endpoint.target_same_namespace hsm_state as namespace

      method private of_json json rd =
        let ok nid passphrase =
          Hsm.User.set_passphrase hsm_state nid ~passphrase >>= function
          | Ok () -> Wm.continue true rd
          | Error e -> Endpoint.respond_error e rd
        in
        let ok id =
          Json.decode_passphrase json |> Endpoint.err_to_bad_request (ok id) rd
        in
        Endpoint.lookup_path_nid ok rd

      method! resource_exists rd =
        let ok nid =
          Hsm.User.exists hsm_state nid >>= function
          | Ok does_exist -> Wm.continue does_exist rd
          | Error e -> Endpoint.respond_error e rd
        in
        Endpoint.lookup_path_nid ok rd

      method! is_authorized = Access.is_authorized hsm_state ip

      method! forbidden =
        Endpoint.join_ops ~join:( || )
          [
            (* Caller strictly in same namespace as target
               (R-users cannot change N-Users' passphrase) *)
            namespace#forbidden;
            (* Caller is admin or changing its own passphrase *)
            forbidden_admin_or_self_operator hsm_state;
          ]
    end

  class handler_tags hsm_state ip =
    object (self)
      inherit Endpoint.base_with_body_length
      inherit! Endpoint.input_state_validated hsm_state [ `Operational ]
      inherit! Endpoint.no_cache

      inherit!
        Endpoint.target_same_namespace ~root_allowed_for:[ `GET ] hsm_state as namespace

      method private get_json rd =
        let ok nid =
          Hsm.User.get hsm_state nid >>= function
          | Ok info ->
              let tags = Hsm.User.Info.tags info in
              let json = Json.TagSet.to_yojson tags in
              Wm.continue (`String (Yojson.Safe.to_string json)) rd
          | Error e -> Endpoint.respond_error e rd
        in
        Endpoint.lookup_path_nid ok rd

      method! allowed_methods rd = Wm.continue [ `GET ] rd

      method content_types_provided rd =
        Wm.continue [ ("application/json", self#get_json) ] rd

      method content_types_accepted rd = Wm.continue [] rd

      method! resource_exists rd =
        let ok nid =
          Hsm.User.exists hsm_state nid >>= function
          | Ok exists when exists = true -> (
              Hsm.User.get hsm_state nid >>= function
              | Ok info ->
                  let role = Hsm.User.Info.role info in
                  Wm.continue (role = `Operator) rd
              | Error e -> Endpoint.respond_error e rd)
          | Ok _ -> Wm.continue false rd
          | Error e -> Endpoint.respond_error e rd
        in
        Endpoint.lookup_path_nid ok rd

      method! is_authorized = Access.is_authorized hsm_state ip

      method! forbidden =
        Endpoint.join_ops ~join:( || )
          [
            (* Caller is R-User or in same namespace
               (R-Users can see N-Users' taghs) *)
            namespace#forbidden;
            (* Caller is an admin or seeing its own tags *)
            forbidden_admin_or_self_operator hsm_state;
          ]
    end

  class handler_tags_tag hsm_state ip =
    object (self)
      inherit Endpoint.base_with_body_length
      inherit! Endpoint.input_state_validated hsm_state [ `Operational ]
      inherit! Endpoint.role hsm_state `Administrator ip as role
      inherit! Endpoint.target_same_namespace hsm_state as namespace
      inherit! Endpoint.no_cache
      method! allowed_methods rd = Wm.continue [ `PUT; `DELETE ] rd

      method! forbidden =
        (* Check both role and namespace *)
        Endpoint.join_ops ~join:( || ) [ role#forbidden; namespace#forbidden ]

      method content_types_provided rd =
        Wm.continue [ ("application/json", Wm.continue `Empty) ] rd

      method content_types_accepted rd =
        Wm.continue
          [
            ("application/json", self#put_resource);
            ("application/octet-stream", self#put_resource);
          ]
          rd

      method! resource_exists rd =
        let tag_exists info tag =
          let exists = Json.TagSet.mem tag (Hsm.User.Info.tags info) in
          Wm.continue exists rd
        in
        let user_exists nid =
          Hsm.User.get hsm_state nid >>= function
          | Ok info -> Endpoint.lookup_path_info (tag_exists info) "tag" rd
          | Error e -> Endpoint.respond_error e rd
        in
        let ok nid =
          Hsm.User.exists hsm_state nid >>= function
          | Ok exists when exists = true -> user_exists nid
          | Ok _ -> Wm.continue false rd
          | Error e -> Endpoint.respond_error e rd
        in
        Endpoint.lookup_path_nid ok rd

      method private put_resource rd =
        let ok nid tag =
          Hsm.User.add_tag hsm_state nid ~tag >>= function
          | Ok true -> Wm.continue true rd
          | Ok false -> Endpoint.respond_status (`Not_modified, "") rd
          | Error e -> Endpoint.respond_error e rd
        in
        let ok nid =
          Hsm.User.exists hsm_state nid >>= function
          | Ok exists when exists = true ->
              Endpoint.lookup_path_info (ok nid) "tag" rd
          | Ok _ -> Endpoint.respond_status (`Not_found, "") rd
          | Error e -> Endpoint.respond_error e rd
        in
        Endpoint.lookup_path_nid ok rd

      method! delete_resource rd =
        let ok nid tag =
          Hsm.User.remove_tag hsm_state nid ~tag >>= function
          | Ok res -> Wm.continue res rd
          | Error e -> Endpoint.respond_error e rd
        in
        let ok nid = Endpoint.lookup_path_info (ok nid) "tag" rd in
        Endpoint.lookup_path_nid ok rd

      method! is_authorized = Access.is_authorized hsm_state ip
    end
end
