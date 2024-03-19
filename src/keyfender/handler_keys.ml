(* Copyright 2023 - 2023, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

open Lwt.Infix

module Make (Wm : Webmachine.S with type +'a io = 'a Lwt.t) (Hsm : Hsm.S) =
struct
  module Access = Access.Make (Wm) (Hsm)
  module Endpoint = Endpoint.Make (Wm) (Hsm)

  class handler_keys hsm_state ip =
    object (self)
      inherit Endpoint.base_with_body_length
      inherit! Endpoint.input_state_validated hsm_state [ `Operational ]
      inherit! Endpoint.role_operator_get hsm_state ip
      val mutable content_type = None
      val mutable new_id = None

      method private filter_by_restrictions rd =
        match Uri.get_query_param rd.Webmachine.Rd.uri "filter" with
        | None -> false
        | Some _ -> true

      method! known_content_type rd =
        match rd.meth with
        | `POST -> (
            match Cohttp.Header.get rd.req_headers "Content-Type" with
            | None ->
                Logs.err (fun m ->
                    m
                      "There seems to be no header field Content-Type. A \
                       Content-Type must be provided.");
                Wm.continue false rd
            | Some v when String.lowercase_ascii v = "application/json" ->
                Wm.continue true rd
            | Some v -> (
                (*
                  Must end with "\r\n". To be on the safe side, we add it.
                  See https://discuss.ocaml.org/t/multipart-form-data/8411/3
              *)
                match Multipart_form.Content_type.of_string (v ^ "\r\n") with
                | Error (`Msg err) ->
                    Logs.err (fun m ->
                        m "Parsing Content-Type failed with: %s" err);
                    Wm.continue false rd
                | Ok v ->
                    content_type <- Some v;
                    Wm.continue true rd))
        | _ -> Wm.continue true rd

      method private get_json rd =
        let user_id = Endpoint.Access.get_user rd.Webmachine.Rd.req_headers in
        let filter_by_restrictions = self#filter_by_restrictions rd in
        Hsm.Key.list ~filter_by_restrictions ~user_id hsm_state >>= function
        | Error e -> Endpoint.respond_error e rd
        | Ok keys ->
            let items =
              List.map (fun key -> `Assoc [ ("id", `String key) ]) keys
            in
            let body = Yojson.Safe.to_string (`List items) in
            Wm.continue (`String body) rd

      method private set_json rd =
        let cc hdr = Cohttp.Header.remove hdr "location" in
        let rd = Webmachine.Rd.with_resp_headers cc rd in
        let body = rd.Webmachine.Rd.req_body in
        Cohttp_lwt.Body.to_string body >>= fun content ->
        (* must succeed since we set it ourselves, and webmachine ensures that it already happened. *)
        let id = Option.get new_id in
        let ok (key : Json.private_key_req) =
          Hsm.Key.add_json hsm_state ~id key.mechanisms key.typ key.priv
            key.restrictions
          >>= function
          | Ok () ->
              let cc hdr =
                Cohttp.Header.add hdr "location" ("/api/v1/keys/" ^ id)
              in
              let body =
                `Assoc [ ("id", `String id) ] |> Yojson.Basic.to_string
              in
              let rd' =
                Webmachine.Rd.with_resp_headers cc
                  { rd with resp_body = `String body }
              in
              Wm.continue true rd'
          | Error e -> Endpoint.respond_error e rd
        in
        Json.decode Json.private_key_req_of_yojson content
        |> Endpoint.err_to_bad_request ok rd

      method private set_multipart rd =
        let cc hdr = Cohttp.Header.remove hdr "location" in
        let rd = Webmachine.Rd.with_resp_headers cc rd in
        let body = rd.Webmachine.Rd.req_body in
        Cohttp_lwt.Body.to_string body >>= fun content ->
        let content_type = Option.get content_type in
        match Multipart_form.of_string_to_list content content_type with
        | Ok (_, [ (x, p1); (y, p2) ]) -> (
            let params, pem = if x < y then (p1, p2) else (p2, p1) in
            match Json.(decode private_key_multipart_req_of_yojson params) with
            | Error e -> Endpoint.respond_error (Bad_request, e) rd
            | Ok { mechanisms; restrictions } -> (
                (* must succeed since we set it ourselves, and webmachine ensures that it already happened. *)
                let id = Option.get new_id in
                Hsm.Key.add_pem hsm_state ~id mechanisms pem restrictions
                >>= function
                | Ok () ->
                    let cc hdr =
                      Cohttp.Header.add hdr "location" ("/api/v1/keys/" ^ id)
                    in
                    let body =
                      `Assoc [ ("id", `String id) ] |> Yojson.Basic.to_string
                    in
                    let rd' =
                      Webmachine.Rd.with_resp_headers cc
                        { rd with resp_body = `String body }
                    in
                    Wm.continue true rd'
                | Error e -> Endpoint.respond_error e rd))
        | _ ->
            Endpoint.respond_error
              ( Bad_request,
                "Invalid multipart request, must have exactly two parts: json \
                 parameters and pem file." )
              rd

      method! post_is_create rd = Wm.continue true rd

      method! create_path rd =
        let id = Hsm.generate_id () in
        new_id <- Some id;
        Wm.continue id rd

      method! allowed_methods rd = Wm.continue [ `POST; `GET ] rd

      method content_types_provided rd =
        Wm.continue [ ("application/json", self#get_json) ] rd

      method content_types_accepted rd =
        Wm.continue
          [
            ("application/json", self#set_json);
            ("multipart/form-data", self#set_multipart);
          ]
          rd

      method! generate_etag rd =
        let filter_by_restrictions = self#filter_by_restrictions rd in
        Hsm.Key.list_digest hsm_state ~filter_by_restrictions >>= fun digest ->
        Wm.continue digest rd
    end

  class handler_keys_generate hsm_state ip =
    object (self)
      inherit Endpoint.base_with_body_length
      inherit! Endpoint.input_state_validated hsm_state [ `Operational ]
      inherit! Endpoint.role hsm_state `Administrator ip
      inherit! Endpoint.no_cache
      val mutable new_id = None

      method private set_json rd =
        let cc hdr = Cohttp.Header.remove hdr "location" in
        let rd = Webmachine.Rd.with_resp_headers cc rd in
        let body = rd.Webmachine.Rd.req_body in
        Cohttp_lwt.Body.to_string body >>= fun content ->
        let ok (key : Json.generate_key_req) =
          let id =
            match (key.id, new_id) with
            | "", Some path -> path
            | "", None -> assert false (* can never happen, see above *)
            | id, _ -> id
          in
          Hsm.Key.generate hsm_state ~id key.typ key.mechanisms
            ~length:key.length key.restrictions
          >>= function
          | Ok () ->
              let cc hdr =
                Cohttp.Header.add hdr "location" ("/api/v1/keys/" ^ id)
              in
              let rd' = Webmachine.Rd.with_resp_headers cc rd in
              let body =
                `Assoc [ ("id", `String id) ] |> Yojson.Basic.to_string
              in
              let rd' = { rd' with resp_body = `String body } in
              Wm.continue true rd'
          | Error e -> Endpoint.respond_error e rd
        in
        Json.decode_generate_key_req content
        |> Endpoint.err_to_bad_request ok rd

      method! post_is_create rd = Wm.continue true rd

      method! create_path rd =
        let id = Hsm.generate_id () in
        let uri =
          let parts = Astring.String.cuts ~sep:"/" (Uri.path rd.uri) in
          let without_last =
            match List.rev parts with _ :: tl -> List.rev tl | x -> x
          in
          Uri.with_path rd.uri (Astring.String.concat ~sep:"/" without_last)
        in
        new_id <- Some id;
        let rd' = { rd with uri } in
        Wm.continue id rd'

      method! allowed_methods rd = Wm.continue [ `POST ] rd

      method content_types_provided rd =
        Wm.continue [ ("application/json", Wm.continue `Empty) ] rd

      method content_types_accepted rd =
        Wm.continue [ ("application/json", self#set_json) ] rd
    end

  class handler_cert hsm_state ip =
    object (self)
      inherit Endpoint.base_with_body_length
      inherit! Endpoint.input_state_validated hsm_state [ `Operational ]
      inherit! Endpoint.role_operator_get hsm_state ip
      method! allowed_methods rd = Wm.continue [ `PUT; `GET; `DELETE ] rd

      method! known_content_type rd =
        match rd.meth with
        | `PUT -> (
            match Cohttp.Header.get rd.req_headers "Content-Type" with
            (* Convert to lower case, as mime types are case insensitive.
               From https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types
               MIME types are case-insensitive but are traditionally written in lowercase. The parameter values can be case-sensitive.
            *)
            | Some v ->
                Wm.continue
                  (v |> String.lowercase_ascii = "application/octet-stream")
                  rd
            | None -> Wm.continue false rd)
        | _ -> Wm.continue true rd

      method content_types_provided rd =
        (*
           Execution of this callback for a get request is assured by webmachines, version 3, states C3 and C4. State Machine Diagram: https://raw.githubusercontent.com/webmachine/webmachine/develop/docs/http-headers-status-v3.png
           If the client provides the Accept header, it is checked if it matches one of the Content-Types from content_types_provided.
           If so, this callback is called to encode the body, otherwise the call fails.
           If no Accept header is provided, the first value of the list returned by content_type_provided is assumed.
        *)
        Wm.continue [ ("application/octet-stream", self#get_cert) ] rd

      method content_types_accepted rd =
        Wm.continue [ ("application/octet-stream", self#process_put) ] rd

      method! generate_etag rd =
        let id = Webmachine.Rd.lookup_path_info_exn "id" rd in
        Hsm.Key.digest hsm_state ~id >>= fun digest -> Wm.continue digest rd

      method! resource_exists rd =
        let ok id =
          Hsm.Key.exists hsm_state ~id >>= function
          | Ok does_exist -> Wm.continue does_exist rd
          | Error e -> Endpoint.respond_error e rd
        in
        Endpoint.lookup_path_info ok "id" rd

      method private process_put rd =
        let body = rd.Webmachine.Rd.req_body in
        Cohttp_lwt.Body.to_string body >>= fun content ->
        let ok id =
          Hsm.Key.exists hsm_state ~id >>= function
          | Error e -> Endpoint.respond_error e rd
          | Ok does_exist -> (
              if not does_exist then
                let cc hdr =
                  Cohttp.Header.replace hdr "content-type" "application/json"
                in
                let rd' = Webmachine.Rd.with_resp_headers cc rd in
                Wm.respond
                  ~body:(`String (Json.error "keyID not found"))
                  404 rd'
              else
                match Cohttp.Header.get rd.req_headers "content-type" with
                | Some "application/octet-stream" -> (
                    (*
                        For now, the only allowed Content-Type is application/octet-stream.
                        It was decided to also store the Content-Type, to easily add more content types later.
                    *)
                    Hsm.Key.set_cert hsm_state ~id
                      ~content_type:"application/octet-stream" content
                    >>= function
                    | Ok () ->
                        Wm.respond (Cohttp.Code.code_of_status `Created) rd
                    | Error e -> Endpoint.respond_error e rd)
                | Some _ ->
                    Endpoint.respond_error
                      ( Bad_request,
                        "Content-Type must be application/octet-stream." )
                      rd
                | None ->
                    Endpoint.respond_error
                      (Bad_request, "Missing Content-Type in header.")
                      rd)
        in
        Endpoint.lookup_path_info ok "id" rd

      method private get_cert rd =
        let ok id =
          Hsm.Key.get_cert hsm_state ~id >>= function
          | Error e -> Endpoint.respond_error e rd
          | Ok None -> Wm.respond (Cohttp.Code.code_of_status `Not_found) rd
          | Ok (Some (content_type, data)) ->
              let add_ct headers =
                Cohttp.Header.replace headers "Content-Type" content_type
              in
              Wm.continue (`String data)
                (Webmachine.Rd.with_resp_headers add_ct rd)
        in
        Endpoint.lookup_path_info ok "id" rd

      method! delete_resource rd =
        let ok id =
          Hsm.Key.remove_cert hsm_state ~id >>= function
          | Ok () -> Wm.continue true rd
          | Error e -> Endpoint.respond_error e rd
        in
        Endpoint.lookup_path_info ok "id" rd
    end

  class handler hsm_state ip =
    object (self)
      inherit Endpoint.base_with_body_length
      inherit! Endpoint.input_state_validated hsm_state [ `Operational ]
      inherit! Endpoint.role_operator_get hsm_state ip
      val mutable content_type = None

      method! known_content_type rd =
        match rd.meth with
        | `PUT -> (
            match Cohttp.Header.get rd.req_headers "Content-Type" with
            | None ->
                Logs.err (fun m ->
                    m
                      "There seems to be no header field Content-Type. A \
                       Content-Type must be provided.");
                Wm.continue false rd
            | Some v when String.lowercase_ascii v = "application/json" ->
                Wm.continue true rd
            | Some v -> (
                (*
                  Must end with "\r\n". To be on the safe side, we add it.
                  See https://discuss.ocaml.org/t/multipart-form-data/8411/3
              *)
                match Multipart_form.Content_type.of_string (v ^ "\r\n") with
                | Error (`Msg err) ->
                    Logs.err (fun m ->
                        m "Parsing Content-Type failed with: %s" err);
                    Wm.continue false rd
                | Ok v ->
                    content_type <- Some v;
                    Wm.continue true rd))
        | _ -> Wm.continue true rd

      method private get_json rd =
        let ok id =
          Hsm.Key.get_json ~id hsm_state >>= function
          | Error e -> Endpoint.respond_error e rd
          | Ok public_key ->
              let body = Yojson.Safe.to_string public_key in
              Wm.continue (`String body) rd
        in
        Endpoint.lookup_path_info ok "id" rd

      method private set_json rd =
        let body = rd.Webmachine.Rd.req_body in
        Cohttp_lwt.Body.to_string body >>= fun content ->
        let ok id (key : Json.private_key_req) =
          Hsm.Key.add_json hsm_state ~id key.mechanisms key.typ key.priv
            key.restrictions
          >>= function
          | Ok () -> Wm.continue true rd
          | Error e -> Endpoint.respond_error e rd
        in
        let ok id =
          Endpoint.err_to_bad_request (ok id) rd
            (Json.decode Json.private_key_req_of_yojson content)
        in
        Endpoint.lookup_path_info ok "id" rd

      method private set_multipart rd =
        let body = rd.Webmachine.Rd.req_body in
        Cohttp_lwt.Body.to_string body >>= fun content ->
        let content_type = Option.get content_type in
        match Multipart_form.of_string_to_list content content_type with
        | Ok (_, [ (x, p1); (y, p2) ]) -> (
            let params, pem = if x < y then (p1, p2) else (p2, p1) in
            match Json.(decode private_key_multipart_req_of_yojson params) with
            | Error e -> Endpoint.respond_error (Bad_request, e) rd
            | Ok { mechanisms; restrictions } ->
                let ok id =
                  Hsm.Key.add_pem hsm_state ~id mechanisms pem restrictions
                  >>= function
                  | Ok () -> Wm.continue true rd
                  | Error e -> Endpoint.respond_error e rd
                in
                Endpoint.lookup_path_info ok "id" rd)
        | _ ->
            Endpoint.respond_error
              ( Bad_request,
                "Invalid multipart request, must have exactly two parts: json \
                 parameters and pem file." )
              rd

      method! resource_exists rd =
        let ok id =
          Hsm.Key.exists hsm_state ~id >>= function
          | Ok does_exist -> Wm.continue does_exist rd
          | Error e -> Endpoint.respond_error e rd
        in
        Endpoint.lookup_path_info ok "id" rd

      method! delete_resource rd =
        let ok id =
          Hsm.Key.remove hsm_state ~id >>= function
          | Ok () -> Wm.continue true rd
          | Error e -> Endpoint.respond_error e rd
        in
        Endpoint.lookup_path_info ok "id" rd

      method! allowed_methods rd = Wm.continue [ `PUT; `GET; `DELETE ] rd

      method content_types_provided rd =
        Wm.continue [ ("application/json", self#get_json) ] rd

      method content_types_accepted rd =
        Wm.continue
          [
            ("application/json", self#set_json);
            ("multipart/form-data", self#set_multipart);
          ]
          rd

      method! generate_etag rd =
        let id = Webmachine.Rd.lookup_path_info_exn "id" rd in
        Hsm.Key.digest hsm_state ~id >>= fun digest -> Wm.continue digest rd
    end

  class handler_public hsm_state ip =
    object (self)
      inherit Endpoint.base_with_body_length
      inherit! Endpoint.input_state_validated hsm_state [ `Operational ]

      method private get_pem rd =
        let ok id =
          Hsm.Key.get_pem hsm_state ~id >>= function
          | Error e -> Endpoint.respond_error e rd
          | Ok data -> Wm.continue (`String data) rd
        in
        Endpoint.lookup_path_info ok "id" rd

      method! resource_exists rd =
        let ok id =
          Hsm.Key.exists hsm_state ~id >>= function
          | Ok does_exist -> Wm.continue does_exist rd
          | Error e -> Endpoint.respond_error e rd
        in
        Endpoint.lookup_path_info ok "id" rd

      method! allowed_methods rd = Wm.continue [ `GET ] rd

      method content_types_provided rd =
        Wm.continue [ ("application/x-pem-file", self#get_pem) ] rd

      method content_types_accepted rd = Wm.continue [] rd
      method! is_authorized = Access.is_authorized hsm_state ip

      method! forbidden rd =
        Access.forbidden hsm_state `Administrator rd >>= fun not_an_admin ->
        Access.forbidden hsm_state `Operator rd >>= fun not_an_operator ->
        Wm.continue (not_an_admin && not_an_operator) rd

      method! generate_etag rd =
        let id = Webmachine.Rd.lookup_path_info_exn "id" rd in
        Hsm.Key.digest hsm_state ~id >>= fun digest -> Wm.continue digest rd
    end

  class handler_csr hsm_state ip =
    object (self)
      inherit Endpoint.base_with_body_length
      inherit! Endpoint.input_state_validated hsm_state [ `Operational ]
      inherit! Endpoint.no_cache

      method private csr_pem rd =
        let body = rd.Webmachine.Rd.req_body in
        Cohttp_lwt.Body.to_string body >>= fun content ->
        let ok id =
          match Json.decode_subject content with
          | Error e -> Endpoint.respond_error (Bad_request, e) rd
          | Ok subject -> (
              Hsm.Key.csr_pem hsm_state ~id subject >>= function
              | Error e -> Endpoint.respond_error e rd
              | Ok csr_pem ->
                  let rd' = { rd with resp_body = `String csr_pem } in
                  Wm.continue true rd')
        in
        Endpoint.lookup_path_info ok "id" rd

      method! resource_exists rd =
        let ok id =
          Hsm.Key.exists hsm_state ~id >>= function
          | Ok does_exist -> Wm.continue does_exist rd
          | Error e -> Endpoint.respond_error e rd
        in
        Endpoint.lookup_path_info ok "id" rd

      method! process_post rd = self#csr_pem rd
      method! allowed_methods rd = Wm.continue [ `POST ] rd

      method content_types_provided rd =
        Wm.continue [ ("application/x-pem-file", Wm.continue `Empty) ] rd

      method content_types_accepted rd =
        Wm.continue [ ("application/json", self#csr_pem) ] rd

      method! is_authorized = Access.is_authorized hsm_state ip

      method! forbidden rd =
        Access.forbidden hsm_state `Administrator rd >>= fun not_an_admin ->
        Access.forbidden hsm_state `Operator rd >>= fun not_an_operator ->
        Wm.continue (not_an_admin && not_an_operator) rd
    end

  class handler_decrypt hsm_state ip =
    object (self)
      inherit Endpoint.base_with_large_body_length
      inherit! Endpoint.input_state_validated hsm_state [ `Operational ]
      inherit! Endpoint.role hsm_state `Operator ip
      inherit! Endpoint.no_cache

      method private decrypt rd =
        let body = rd.Webmachine.Rd.req_body in
        Cohttp_lwt.Body.to_string body >>= fun content ->
        let ok id (dec : Json.decrypt_req) =
          let user_id = Endpoint.Access.get_user rd.Webmachine.Rd.req_headers in
          Hsm.Key.decrypt hsm_state ~id ~user_id ~iv:dec.iv dec.mode
            dec.encrypted
          >>= function
          | Ok decrypted ->
              let json =
                Yojson.Safe.to_string
                  (`Assoc [ ("decrypted", `String decrypted) ])
              in
              let rd' = { rd with resp_body = `String json } in
              Wm.continue true rd'
          | Error e -> Endpoint.respond_error e rd
        in
        let ok id =
          Json.decode Json.decrypt_req_of_yojson content
          |> Endpoint.err_to_bad_request (ok id) rd
        in
        Endpoint.lookup_path_info ok "id" rd

      method! resource_exists rd =
        let ok id =
          Hsm.Key.exists hsm_state ~id >>= function
          | Ok does_exist -> Wm.continue does_exist rd
          | Error e -> Endpoint.respond_error e rd
        in
        Endpoint.lookup_path_info ok "id" rd

      method! process_post rd = self#decrypt rd
      method! allowed_methods rd = Wm.continue [ `POST ] rd

      method content_types_provided rd =
        Wm.continue [ ("application/json", Wm.continue `Empty) ] rd

      method content_types_accepted rd =
        Wm.continue [ ("application/json", self#decrypt) ] rd
    end

  class handler_encrypt hsm_state ip =
    object (self)
      inherit Endpoint.base_with_large_body_length
      inherit! Endpoint.input_state_validated hsm_state [ `Operational ]
      inherit! Endpoint.role hsm_state `Operator ip
      inherit! Endpoint.no_cache

      method private encrypt rd =
        let body = rd.Webmachine.Rd.req_body in
        Cohttp_lwt.Body.to_string body >>= fun content ->
        let ok id (dec : Json.encrypt_req) =
          let user_id = Endpoint.Access.get_user rd.Webmachine.Rd.req_headers in
          Hsm.Key.encrypt hsm_state ~id ~user_id ~iv:dec.iv dec.mode dec.message
          >>= function
          | Ok (encrypted, iv) ->
              let iv =
                match iv with Some iv -> [ ("iv", `String iv) ] | None -> []
              in
              let l = ("encrypted", `String encrypted) :: iv in
              let json = Yojson.Safe.to_string (`Assoc l) in
              let rd' = { rd with resp_body = `String json } in
              Wm.continue true rd'
          | Error e -> Endpoint.respond_error e rd
        in
        let ok id =
          Json.decode Json.encrypt_req_of_yojson content
          |> Endpoint.err_to_bad_request (ok id) rd
        in
        Endpoint.lookup_path_info ok "id" rd

      method! resource_exists rd =
        let ok id =
          Hsm.Key.exists hsm_state ~id >>= function
          | Ok does_exist -> Wm.continue does_exist rd
          | Error e -> Endpoint.respond_error e rd
        in
        Endpoint.lookup_path_info ok "id" rd

      method! process_post rd = self#encrypt rd
      method! allowed_methods rd = Wm.continue [ `POST ] rd

      method content_types_provided rd =
        Wm.continue [ ("application/json", Wm.continue `Empty) ] rd

      method content_types_accepted rd =
        Wm.continue [ ("application/json", self#encrypt) ] rd
    end

  class handler_sign hsm_state ip =
    object (self)
      inherit Endpoint.base_with_large_body_length
      inherit! Endpoint.input_state_validated hsm_state [ `Operational ]
      inherit! Endpoint.role hsm_state `Operator ip
      inherit! Endpoint.no_cache

      method private sign rd =
        let body = rd.Webmachine.Rd.req_body in
        Cohttp_lwt.Body.to_string body >>= fun content ->
        let ok id (sign : Json.sign_req) =
          let user_id = Endpoint.Access.get_user rd.Webmachine.Rd.req_headers in
          Hsm.Key.sign hsm_state ~id ~user_id sign.mode sign.message
          >>= function
          | Ok signature ->
              let json =
                Yojson.Safe.to_string
                  (`Assoc [ ("signature", `String signature) ])
              in
              let rd' = { rd with resp_body = `String json } in
              Wm.continue true rd'
          | Error e -> Endpoint.respond_error e rd
        in
        let ok id =
          Json.decode Json.sign_req_of_yojson content
          |> Endpoint.err_to_bad_request (ok id) rd
        in
        Endpoint.lookup_path_info ok "id" rd

      method! resource_exists rd =
        let ok id =
          Hsm.Key.exists hsm_state ~id >>= function
          | Ok does_exist -> Wm.continue does_exist rd
          | Error e -> Endpoint.respond_error e rd
        in
        Endpoint.lookup_path_info ok "id" rd

      method! process_post rd = self#sign rd
      method! allowed_methods rd = Wm.continue [ `POST ] rd

      method content_types_provided rd =
        Wm.continue [ ("application/json", Wm.continue `Empty) ] rd

      method content_types_accepted rd =
        Wm.continue [ ("application/json", self#sign) ] rd
    end

  class handler_restrictions_tags hsm_state ip =
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
        let tag_exists (restrictions : Json.restrictions) tag =
          let exists = Json.TagSet.mem tag restrictions.tags in
          Wm.continue exists rd
        in
        let key_exists id =
          Hsm.Key.get_restrictions hsm_state ~id >>= function
          | Ok restrictions ->
              Endpoint.lookup_path_info (tag_exists restrictions) "tag" rd
          | Error e -> Endpoint.respond_error e rd
        in
        let ok_key_id id =
          Hsm.Key.exists hsm_state ~id >>= function
          | Ok exists when exists = true -> key_exists id
          | Ok _ -> Wm.continue false rd
          | Error e -> Endpoint.respond_error e rd
        in
        Endpoint.lookup_path_info ok_key_id "id" rd

      method private put_resource rd =
        let ok_tag ~id tag =
          Hsm.Key.add_restriction_tags hsm_state ~id ~tag >>= function
          | Ok true -> Wm.continue true rd
          | Ok false -> Endpoint.respond_status (`Not_modified, "") rd
          | Error e -> Endpoint.respond_error e rd
        in
        let ok_key_id id =
          Hsm.Key.exists hsm_state ~id >>= function
          | Ok exists when exists = true ->
              Endpoint.lookup_path_info (ok_tag ~id) "tag" rd
          | Ok _ -> Endpoint.respond_status (`Not_found, "key not found") rd
          | Error e -> Endpoint.respond_error e rd
        in
        Endpoint.lookup_path_info ok_key_id "id" rd

      method! delete_resource rd =
        let ok_tag ~id tag =
          Hsm.Key.remove_restriction_tags hsm_state ~id ~tag >>= function
          | Ok res -> Wm.continue res rd
          | Error e -> Endpoint.respond_error e rd
        in
        let ok_key_id id = Endpoint.lookup_path_info (ok_tag ~id) "tag" rd in
        Endpoint.lookup_path_info ok_key_id "id" rd

      method! is_authorized = Access.is_authorized hsm_state ip
    end
end
