open Lwt.Infix

module Make (Wm : Webmachine.S with type +'a io = 'a Lwt.t) (Hsm : Hsm.S) = struct
  module Access = Access.Make(Wm)(Hsm)
  module Endpoint = Endpoint.Make(Wm)(Hsm)

  class handler_keys hsm_state ip = object(self)
    inherit Endpoint.base_with_body_length
    inherit !Endpoint.input_state_validated hsm_state [ `Operational ]
    inherit !Endpoint.role_operator_get hsm_state ip

    method private get_json rd =
      Hsm.Key.list hsm_state >>= function
      | Error e -> Endpoint.respond_error e rd
      | Ok keys ->
        let items = List.map (fun key -> `Assoc [ "key", `String key ]) keys in
        let body = Yojson.Safe.to_string (`List items) in
        Wm.continue (`String body) rd

    method private set_json rd =
      let body = rd.Webmachine.Rd.req_body in
      Cohttp_lwt.Body.to_string body >>= fun content ->
      let id = match Cohttp.Header.get rd.req_headers "new_id" with
      | None -> assert false | Some path -> path in
      let ok (key : Json.private_key_req) =
        Hsm.Key.add_json hsm_state ~id key.mechanisms key.algorithm key.key >>= function
        | Ok () -> Wm.continue true rd
        | Error e -> Endpoint.respond_error e rd
      in
      Json.decode Json.private_key_req_of_yojson content |>
      Endpoint.err_to_bad_request ok rd

    method private set_pem rd =
      let body = rd.Webmachine.Rd.req_body in
      Cohttp_lwt.Body.to_string body >>= fun content ->
      let mechanisms =
        match Uri.get_query_param rd.Webmachine.Rd.uri "mechanisms" with
        | Some ms -> Json.mechanisms_of_string ms
        | None -> Error "Request is missing mechanisms."
      in
      let id = match Cohttp.Header.get rd.req_headers "new_id" with
        | None -> assert false (* this can't happen since we set it ourselves,
                                  and webmachine ensures that it already happened. *)
        | Some path -> path
      in
      let ok mechanisms =
        Hsm.Key.add_pem hsm_state ~id mechanisms content >>= function
        | Ok () -> Wm.continue true rd
        | Error e -> Endpoint.respond_error e rd
      in
      Endpoint.err_to_bad_request ok rd mechanisms

    method! post_is_create rd =
      Wm.continue true rd

    method! create_path rd =
      let path = Hsm.generate_id () in
      let rd' = { rd with req_headers = Cohttp.Header.add rd.req_headers "new_id" path } in
      Wm.continue path rd'

    method! allowed_methods rd =
      Wm.continue [`POST; `GET ] rd

    method content_types_provided rd =
      Wm.continue [ ("application/json", self#get_json) ] rd

    method content_types_accepted rd =
      Wm.continue [
        ("application/json", self#set_json) ;
        ("application/x-pem-file", self#set_pem)
      ] rd

    method! generate_etag rd =
      Hsm.Key.list_digest hsm_state >>= fun digest ->
      Wm.continue digest rd
  end

  class handler_keys_generate hsm_state ip = object(self)
    inherit Endpoint.base_with_body_length
    inherit !Endpoint.input_state_validated hsm_state [ `Operational ]
    inherit !Endpoint.role hsm_state `Administrator ip
    inherit !Endpoint.no_cache

    method private set_json rd =
      let body = rd.Webmachine.Rd.req_body in
      Cohttp_lwt.Body.to_string body >>= fun content ->
      let ok (key : Json.generate_key_req) =
        let id = match key.id, Cohttp.Header.get rd.req_headers "new_id" with
        | "", Some path -> path
        | "", None -> assert false (* can never happen, see above *)
        | id, _ -> id
        in
        Hsm.Key.generate hsm_state ~id key.algorithm key.mechanisms ~length:key.length >>= function
        | Ok () -> Wm.continue true rd
        | Error e -> Endpoint.respond_error e rd
      in
      Json.decode_generate_key_req content |>
      Endpoint.err_to_bad_request ok rd

    method! post_is_create rd =
      Wm.continue true rd

    method! create_path rd =
      let path = Hsm.generate_id () in
      let uri =
        let parts = Astring.String.cuts ~sep:"/" (Uri.path rd.uri) in
        let without_last = match List.rev parts with
          | _::tl -> List.rev tl
          | x -> x
        in
        Uri.with_path rd.uri (Astring.String.concat ~sep:"/" without_last)
      in
      let rd' = { rd with req_headers = Cohttp.Header.add rd.req_headers "new_id" path ; uri } in
      Wm.continue path rd'

    method! allowed_methods rd =
      Wm.continue [`POST] rd

    method content_types_provided rd =
      Wm.continue [ ("application/json", Wm.continue `Empty) ] rd

    method content_types_accepted rd =
      Wm.continue [
        ("application/json", self#set_json)
      ] rd
  end

  class handler hsm_state ip = object(self)
    inherit Endpoint.base_with_body_length
    inherit !Endpoint.input_state_validated hsm_state [ `Operational ]
    inherit !Endpoint.role_operator_get hsm_state ip

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
        Hsm.Key.add_json hsm_state ~id key.mechanisms key.algorithm key.key >>= function
        | Ok () -> Wm.continue true rd
        | Error e -> Endpoint.respond_error e rd
      in
      let ok id =
        Endpoint.err_to_bad_request (ok id) rd
          (Json.decode Json.private_key_req_of_yojson content)
      in
      Endpoint.lookup_path_info ok "id" rd

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

    method! allowed_methods rd =
      Wm.continue [`PUT; `GET; `DELETE ] rd

    method content_types_provided rd =
      Wm.continue [ ("application/json", self#get_json) ] rd

    method content_types_accepted rd =
      Wm.continue [
        ("application/json", self#set_json)
      ] rd

    method! generate_etag rd =
      let id = Webmachine.Rd.lookup_path_info_exn "id" rd in
      Hsm.Key.digest hsm_state ~id >>= fun digest ->
      Wm.continue digest rd
  end

  class handler_public hsm_state ip = object(self)
    inherit Endpoint.base_with_body_length
    inherit !Endpoint.input_state_validated hsm_state [ `Operational ]

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

    method! allowed_methods rd =
      Wm.continue [`GET ] rd

    method content_types_provided rd =
      Wm.continue [ ("application/x-pem-file", self#get_pem) ] rd

    method content_types_accepted rd =
      Wm.continue [ ] rd

    method! is_authorized = Access.is_authorized hsm_state ip

    method! forbidden rd =
      Access.forbidden hsm_state `Administrator rd >>= fun not_an_admin ->
      Access.forbidden hsm_state `Operator rd >>= fun not_an_operator ->
      Wm.continue (not_an_admin && not_an_operator) rd

    method! generate_etag rd =
      let id = Webmachine.Rd.lookup_path_info_exn "id" rd in
      Hsm.Key.digest hsm_state ~id >>= fun digest ->
      Wm.continue digest rd
  end

  class handler_csr hsm_state ip = object(self)
    inherit Endpoint.base_with_body_length
    inherit !Endpoint.input_state_validated hsm_state [ `Operational ]
    inherit !Endpoint.no_cache

    method private csr_pem rd =
      let body = rd.Webmachine.Rd.req_body in
      Cohttp_lwt.Body.to_string body >>= fun content ->
      let ok id =
        match Json.decode_subject content with
        | Error e -> Endpoint.respond_error (Bad_request, e) rd
        | Ok subject ->
          Hsm.Key.csr_pem hsm_state ~id subject >>= function
          | Error e -> Endpoint.respond_error e rd
          | Ok csr_pem ->
            let rd' = { rd with resp_body = `String csr_pem } in
            Wm.continue true rd'
      in
      Endpoint.lookup_path_info ok "id" rd

    method! resource_exists rd =
      let ok id =
        Hsm.Key.exists hsm_state ~id >>= function
        | Ok does_exist -> Wm.continue does_exist rd
        | Error e -> Endpoint.respond_error e rd
      in
      Endpoint.lookup_path_info ok "id" rd

    method !process_post rd =
      self#csr_pem rd

    method! allowed_methods rd =
      Wm.continue [`POST ] rd

    method content_types_provided rd =
      Wm.continue [ ("application/json", Wm.continue `Empty) ] rd

    method content_types_accepted rd =
      Wm.continue [
        ("application/x-pem-file", self#csr_pem)
      ] rd

    method! is_authorized = Access.is_authorized hsm_state ip

    method! forbidden rd =
      Access.forbidden hsm_state `Administrator rd >>= fun not_an_admin ->
      Access.forbidden hsm_state `Operator rd >>= fun not_an_operator ->
      Wm.continue (not_an_admin && not_an_operator) rd
  end

  class handler_decrypt hsm_state ip = object(self)
    inherit Endpoint.base_with_body_length
    inherit !Endpoint.input_state_validated hsm_state [ `Operational ]
    inherit !Endpoint.role hsm_state `Operator ip
    inherit !Endpoint.no_cache

    method private decrypt rd =
      let body = rd.Webmachine.Rd.req_body in
      Cohttp_lwt.Body.to_string body >>= fun content ->
      let ok id (dec : Json.decrypt_req) =
        Hsm.Key.decrypt hsm_state ~id dec.mode dec.encrypted >>= function
        | Ok decrypted ->
          let json = Yojson.Safe.to_string (`Assoc [ "decrypted", `String decrypted ]) in
          let rd' = { rd with resp_body = `String json } in
          Wm.continue true rd'
        | Error e -> Endpoint.respond_error e rd
      in
      let ok id =
        Json.decode Json.decrypt_req_of_yojson content |>
        Endpoint.err_to_bad_request (ok id) rd
      in
      Endpoint.lookup_path_info ok "id" rd

    method! resource_exists rd =
      let ok id =
        Hsm.Key.exists hsm_state ~id >>= function
        | Ok does_exist -> Wm.continue does_exist rd
        | Error e -> Endpoint.respond_error e rd
      in
      Endpoint.lookup_path_info ok "id" rd

    method !process_post rd =
      self#decrypt rd

    method! allowed_methods rd =
      Wm.continue [`POST ] rd

    method content_types_provided rd =
      Wm.continue [ ("application/json", Wm.continue `Empty) ] rd

    method content_types_accepted rd =
      Wm.continue [ ("application/json", self#decrypt) ] rd
  end

  class handler_sign hsm_state ip = object(self)
    inherit Endpoint.base_with_body_length
    inherit !Endpoint.input_state_validated hsm_state [ `Operational ]
    inherit !Endpoint.role hsm_state `Operator ip
    inherit !Endpoint.no_cache

    method private sign rd =
      let body = rd.Webmachine.Rd.req_body in
      Cohttp_lwt.Body.to_string body >>= fun content ->
      let ok id (sign : Json.sign_req) =
        Hsm.Key.sign hsm_state ~id sign.mode sign.message >>= function
        | Ok signature ->
          let json = Yojson.Safe.to_string (`Assoc [ "signature", `String signature ]) in
          let rd' = { rd with resp_body = `String json } in
          Wm.continue true rd'
        | Error e -> Endpoint.respond_error e rd
      in
      let ok id =
        Json.decode Json.sign_req_of_yojson content |>
        Endpoint.err_to_bad_request (ok id) rd
      in
      Endpoint.lookup_path_info ok "id" rd

    method! resource_exists rd =
      let ok id =
        Hsm.Key.exists hsm_state ~id >>= function
        | Ok does_exist -> Wm.continue does_exist rd
        | Error e -> Endpoint.respond_error e rd
      in
      Endpoint.lookup_path_info ok "id" rd

    method !process_post rd =
      self#sign rd

    method! allowed_methods rd =
      Wm.continue [`POST ] rd

    method content_types_provided rd =
      Wm.continue [ ("application/json", Wm.continue `Empty) ] rd

    method content_types_accepted rd =
      Wm.continue [ ("application/json", self#sign) ] rd
  end

  let allowed_content_types = [
    "application/json" ; (* Arbitrary JSON data *)
    "application/x-pem-file" ; (* Certificate in PEM format *)
    "application/x-x509-ca-cert" ; (* Certificate in DER format *)
    "application/octet-stream" ; (* arbitrary binary keys *)
    "text/plain" ; (* base64 encoded keys, arbitrary "configuration data" *)
    "application/pgp-keys" ; (* OpenPGP keys *)
  ]

  class handler_cert hsm_state ip = object(self)
    inherit Endpoint.base_with_body_length
    inherit !Endpoint.input_state_validated hsm_state [ `Operational ]
    inherit !Endpoint.role_operator_get hsm_state ip

    method private get_cert rd =
      let ok id =
        Hsm.Key.get_cert hsm_state ~id >>= function
        | Error e -> Endpoint.respond_error e rd
        | Ok None -> Wm.respond (Cohttp.Code.code_of_status `Not_found) rd
        | Ok (Some (content_type, data)) ->
          let add_ct headers =
            Cohttp.Header.replace headers "content-type" content_type
          in
          Wm.continue (`String data) (Webmachine.Rd.with_resp_headers add_ct rd)
      in
      Endpoint.lookup_path_info ok "id" rd

    method! resource_exists rd =
      let ok id =
        Hsm.Key.exists hsm_state ~id >>= function
        | Ok does_exist -> Wm.continue does_exist rd
        | Error e -> Endpoint.respond_error e rd
      in
      Endpoint.lookup_path_info ok "id" rd

    method! delete_resource rd =
      let ok id =
        Hsm.Key.remove_cert hsm_state ~id >>= function
        | Ok () -> Wm.continue true rd
        | Error e -> Endpoint.respond_error e rd
      in
      Endpoint.lookup_path_info ok "id" rd

    method! allowed_methods rd =
      Wm.continue [`PUT; `GET; `DELETE ] rd

    method content_types_provided rd =
      Wm.continue [ ("text/html", self#get_cert) ] rd

    method content_types_accepted rd =
      (* Allow all content types provided by the client, which is not intended
         use of webmachine. We send a response immediately instead of returning
         control to webmachine. *)
      let body = rd.Webmachine.Rd.req_body in
      Cohttp_lwt.Body.to_string body >>= fun content ->
      let ok id =
        Hsm.Key.exists hsm_state ~id >>= function
        | Error e -> Endpoint.respond_error e rd
        | Ok does_exist ->
          if not does_exist then
            let cc hdr = Cohttp.Header.replace hdr "content-type" "application/json" in
            let rd' = Webmachine.Rd.with_resp_headers cc rd in
            Wm.respond ~body:(`String (Json.error "keyID not found")) 404 rd'
          else
            match Cohttp.Header.get rd.req_headers "content-type" with
            | None -> Endpoint.respond_error (Bad_request, "Missing content-type header.") rd
            | Some content_type ->
              if List.mem content_type allowed_content_types then
                Hsm.Key.set_cert hsm_state ~id ~content_type content >>= function
                | Ok () -> Wm.respond (Cohttp.Code.code_of_status `Created) rd
                | Error e -> Endpoint.respond_error e rd
              else
                Endpoint.respond_error (Bad_request, "disallowed content-type") rd
      in
      Endpoint.lookup_path_info ok "id" rd

    method! generate_etag rd =
      let id = Webmachine.Rd.lookup_path_info_exn "id" rd in
      Hsm.Key.digest hsm_state ~id >>= fun digest ->
      Wm.continue digest rd
  end
end
