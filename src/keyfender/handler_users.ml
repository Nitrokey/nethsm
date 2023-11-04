(* Copyright 2023 - 2023, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

open Lwt.Infix

module Make (Wm : Webmachine.S with type +'a io = 'a Lwt.t) (Hsm : Hsm.S) =
struct
  module Access = Access.Make (Wm) (Hsm)
  module Endpoint = Endpoint.Make (Wm) (Hsm)

  class handler_users hsm_state ip =
    object (self)
      inherit Endpoint.base_with_body_length
      inherit! Endpoint.input_state_validated hsm_state [ `Operational ]
      inherit! Endpoint.role hsm_state `Administrator ip

      method private get_json rd =
        Hsm.User.list hsm_state >>= function
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
        let ok (user : Json.user_req) =
          let id =
            match Cohttp.Header.get rd.req_headers "new_id" with
            | None ->
                assert false
                (* this can't happen since we set it ourselves,
                   and webmachine ensures that it already happened. *)
            | Some path -> path
          in
          Hsm.User.add hsm_state ~id ~role:user.role ~name:user.realName
            ~passphrase:user.passphrase
          >>= function
          | Ok () -> Wm.continue true rd
          | Error e -> Endpoint.respond_error e rd
        in
        Json.decode_user_req content |> Endpoint.err_to_bad_request ok rd

      method! post_is_create rd = Wm.continue true rd

      method! create_path rd =
        let path = Hsm.generate_id () in
        let rd' =
          {
            rd with
            req_headers = Cohttp.Header.add rd.req_headers "new_id" path;
          }
        in
        Wm.continue path rd'

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
      inherit! Endpoint.role_operator_get_self hsm_state ip

      method private get_json rd =
        let ok id =
          Hsm.User.get hsm_state ~id >>= function
          | Error e -> Endpoint.respond_error e rd
          | Ok info ->
              let module Info = Hsm.User.Info in
              let user =
                { Json.realName = Info.name info; role = Info.role info }
              in
              let body = Yojson.Safe.to_string (Json.user_res_to_yojson user) in
              Wm.continue (`String body) rd
        in
        Endpoint.lookup_path_info ok "id" rd

      method private set_json rd =
        let body = rd.Webmachine.Rd.req_body in
        Cohttp_lwt.Body.to_string body >>= fun content ->
        let ok id (user : Json.user_req) =
          Hsm.User.add ~id hsm_state ~role:user.role ~name:user.realName
            ~passphrase:user.passphrase
          >>= function
          | Ok _id ->
              let cc hdr =
                Cohttp.Header.replace hdr "Location" (Uri.path rd.uri)
              in
              let rd' = Webmachine.Rd.with_resp_headers cc rd in
              Wm.continue true rd'
          | Error e -> Endpoint.respond_error e rd
        in
        let ok id =
          Endpoint.err_to_bad_request (ok id) rd (Json.decode_user_req content)
        in
        Endpoint.lookup_path_info ok "id" rd

      method! resource_exists rd =
        let ok id =
          Hsm.User.exists hsm_state ~id >>= function
          | Ok does_exist -> Wm.continue does_exist rd
          | Error e -> Endpoint.respond_error e rd
        in
        Endpoint.lookup_path_info ok "id" rd

      method! allowed_methods rd = Wm.continue [ `PUT; `GET; `DELETE ] rd

      method content_types_provided rd =
        Wm.continue [ ("application/json", self#get_json) ] rd

      method content_types_accepted rd =
        Wm.continue [ ("application/json", self#set_json) ] rd

      method! delete_resource rd =
        let ok id =
          Hsm.User.remove hsm_state ~id >>= function
          | Ok () -> Wm.continue true rd
          | Error e -> Endpoint.respond_error e rd
        in
        Endpoint.lookup_path_info ok "id" rd

      method! generate_etag rd =
        let id = Webmachine.Rd.lookup_path_info_exn "id" rd in
        Hsm.User.digest hsm_state ~id >>= fun digest -> Wm.continue digest rd
    end

  class handler_passphrase hsm_state ip =
    object
      inherit Endpoint.base_with_body_length
      inherit! Endpoint.input_state_validated hsm_state [ `Operational ]
      inherit! Endpoint.post_json
      inherit! Endpoint.no_cache

      method private of_json json rd =
        let ok id passphrase =
          Hsm.User.set_passphrase hsm_state ~id ~passphrase >>= function
          | Ok () -> Wm.continue true rd
          | Error e -> Endpoint.respond_error e rd
        in
        let ok id =
          Json.decode_passphrase json |> Endpoint.err_to_bad_request (ok id) rd
        in
        Endpoint.lookup_path_info ok "id" rd

      method! resource_exists rd =
        let ok id =
          Hsm.User.exists hsm_state ~id >>= function
          | Ok does_exist -> Wm.continue does_exist rd
          | Error e -> Endpoint.respond_error e rd
        in
        Endpoint.lookup_path_info ok "id" rd

      method! is_authorized = Access.is_authorized hsm_state ip

      method! forbidden rd =
        (* R-Administrator may GET/PUT/DELETE/POST everything *)
        (* /users/:UserID and /users/:UserID/passphrase *)
        Access.forbidden hsm_state `Administrator rd >>= fun not_an_admin ->
        ((* R-Operator may GET (all!) users, and POST their own passphrase *)
         let id = Webmachine.Rd.lookup_path_info_exn "id" rd in
         if Access.get_user rd.Webmachine.Rd.req_headers = id then
           Access.forbidden hsm_state `Operator rd
         else Lwt.return not_an_admin)
        >>= fun not_an_operator ->
        Wm.continue (not_an_admin && not_an_operator) rd
    end

  class handler_tags hsm_state ip =
    object (self)
      inherit Endpoint.base_with_body_length
      inherit! Endpoint.input_state_validated hsm_state [ `Operational ]
      inherit! Endpoint.no_cache

      method private get_json rd =
        let ok id =
          Hsm.User.get hsm_state ~id >>= function
          | Ok info ->
              let tags = Hsm.User.Info.tags info in
              let json = Json.TagSet.to_yojson tags in
              Wm.continue (`String (Yojson.Safe.to_string json)) rd
          | Error e -> Endpoint.respond_error e rd
        in
        Endpoint.lookup_path_info ok "id" rd

      method! allowed_methods rd = Wm.continue [ `GET ] rd

      method content_types_provided rd =
        Wm.continue [ ("application/json", self#get_json) ] rd

      method content_types_accepted rd = Wm.continue [] rd

      method! resource_exists rd =
        let ok id =
          Hsm.User.exists hsm_state ~id >>= function
          | Ok exists when exists = true -> (
              Hsm.User.get hsm_state ~id >>= function
              | Ok info ->
                  let role = Hsm.User.Info.role info in
                  Wm.continue (role = `Operator) rd
              | Error e -> Endpoint.respond_error e rd)
          | Ok _ -> Wm.continue false rd
          | Error e -> Endpoint.respond_error e rd
        in
        Endpoint.lookup_path_info ok "id" rd

      method! is_authorized = Access.is_authorized hsm_state ip

      method! forbidden rd =
        (* R-Administrator may GET *)
        (* /users/:UserID/tags *)
        Access.forbidden hsm_state `Administrator rd >>= fun not_an_admin ->
        ((* R-Operator may GET (all!) users, and POST their own passphrase *)
         let id = Webmachine.Rd.lookup_path_info_exn "id" rd in
         if Access.get_user rd.Webmachine.Rd.req_headers = id then
           Access.forbidden hsm_state `Operator rd
         else Lwt.return not_an_admin)
        >>= fun not_an_operator ->
        Wm.continue (not_an_admin && not_an_operator) rd
    end

  class handler_tags_tag hsm_state ip =
    object (self)
      inherit Endpoint.base_with_body_length
      inherit! Endpoint.input_state_validated hsm_state [ `Operational ]
      inherit! Endpoint.role hsm_state `Administrator ip
      inherit! Endpoint.no_cache
      method! allowed_methods rd = Wm.continue [ `PUT; `DELETE ] rd

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
        let user_exists id =
          Hsm.User.get hsm_state ~id >>= function
          | Ok info -> Endpoint.lookup_path_info (tag_exists info) "tag" rd
          | Error e -> Endpoint.respond_error e rd
        in
        let ok id =
          Hsm.User.exists hsm_state ~id >>= function
          | Ok exists when exists = true -> user_exists id
          | Ok _ -> Wm.continue false rd
          | Error e -> Endpoint.respond_error e rd
        in
        Endpoint.lookup_path_info ok "id" rd

      method private put_resource rd =
        let ok ~id tag =
          Hsm.User.add_tag hsm_state ~id ~tag >>= function
          | Ok true -> Wm.continue true rd
          | Ok false -> Endpoint.respond_status (`Not_modified, "") rd
          | Error e -> Endpoint.respond_error e rd
        in
        let ok id =
          Hsm.User.exists hsm_state ~id >>= function
          | Ok exists when exists = true ->
              Endpoint.lookup_path_info (ok ~id) "tag" rd
          | Ok _ -> Endpoint.respond_status (`Not_found, "") rd
          | Error e -> Endpoint.respond_error e rd
        in
        Endpoint.lookup_path_info ok "id" rd

      method! delete_resource rd =
        let ok ~id tag =
          Hsm.User.remove_tag hsm_state ~id ~tag >>= function
          | Ok res -> Wm.continue res rd
          | Error e -> Endpoint.respond_error e rd
        in
        let ok id = Endpoint.lookup_path_info (ok ~id) "tag" rd in
        Endpoint.lookup_path_info ok "id" rd

      method! is_authorized = Access.is_authorized hsm_state ip
    end
end
