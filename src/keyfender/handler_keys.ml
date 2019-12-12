open Lwt.Infix

module Make (Wm : Webmachine.S with type +'a io = 'a Lwt.t) (Hsm : Hsm.S) = struct
  module Access = Access.Make(Hsm)
  module Endpoint = Endpoint.Make(Wm)(Hsm)

  type rsa_key = { primeP : string ; primeQ : string ; publicExponent : string } [@@deriving yojson]
  type private_key_request = { purpose: Hsm.Key.purpose ; algorithm: string ; key : rsa_key }[@@deriving yojson]

  type decrypt = { mode : Hsm.Key.decrypt_mode ; encrypted : string }[@@deriving yojson]
  type sign = { mode : Hsm.Key.sign_mode ; message : string }[@@deriving yojson]

  class handler_keys hsm_state = object(self)
    inherit Endpoint.base
    inherit !Endpoint.input_state_validated hsm_state [ `Operational ]
    inherit !Endpoint.role_operator_get hsm_state

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
      let ok (key : private_key_request) =
        let rsa_key = key.key in
        Hsm.Key.add_json hsm_state ~id key.purpose ~p:rsa_key.primeP ~q:rsa_key.primeQ ~e:rsa_key.publicExponent >>= function
        | Ok () -> Wm.continue true rd
        | Error e -> Endpoint.respond_error e rd
      in
      Json.decode private_key_request_of_yojson content |>
      Endpoint.err_to_bad_request ok rd

    method private set_pem rd =
      let body = rd.Webmachine.Rd.req_body in
      Cohttp_lwt.Body.to_string body >>= fun content ->
      let id = match Cohttp.Header.get rd.req_headers "new_id" with
      | None -> assert false | Some path -> path in
      Hsm.Key.add_pem hsm_state ~id Hsm.Key.Encrypt (*TODO*) content >>= function
      | Ok () -> Wm.continue true rd
      | Error e -> Endpoint.respond_error e rd

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
  end

  type generate_request = { purpose: Hsm.Key.purpose ; algorithm : string ; length : int ; id : (string [@default ""]) } [@@deriving yojson]

  class handler_keys_generate hsm_state = object(self)
    inherit Endpoint.base
    inherit !Endpoint.input_state_validated hsm_state [ `Operational ]
    inherit !Endpoint.role hsm_state `Administrator

    method private set_json rd =
      let body = rd.Webmachine.Rd.req_body in
      Cohttp_lwt.Body.to_string body >>= fun content ->
      let ok (key : generate_request) =
        let id = match key.id, Cohttp.Header.get rd.req_headers "new_id" with
        | "", Some path -> path
        | "", None -> assert false
        | id, _ -> id
        in
        Hsm.Key.generate hsm_state ~id key.purpose ~length:key.length >>= function
        | Ok () -> Wm.continue true rd
        | Error e -> Endpoint.respond_error e rd
      in
      Json.decode generate_request_of_yojson content |>
      Endpoint.err_to_bad_request ok rd

    method! post_is_create rd =
      Wm.continue true rd

    method! create_path rd =
      let path = Hsm.generate_id () in
      let rd' = { rd with req_headers = Cohttp.Header.add rd.req_headers "new_id" path } in
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

  class handler hsm_state = object(self)
    inherit Endpoint.base
    inherit !Endpoint.input_state_validated hsm_state [ `Operational ]
    inherit !Endpoint.role_operator_get hsm_state

    method private get_json rd =
      let id = Webmachine.Rd.lookup_path_info_exn "id" rd in
      Hsm.Key.get_json ~id hsm_state >>= function
      | Error e -> Endpoint.respond_error e rd
      | Ok public_key ->
        let body = Yojson.Safe.to_string @@ Hsm.Key.publicKey_to_yojson public_key in
        Wm.continue (`String body) rd

    method private set_json rd =
      let body = rd.Webmachine.Rd.req_body in
      Cohttp_lwt.Body.to_string body >>= fun content ->
      let id = Webmachine.Rd.lookup_path_info_exn "id" rd in
      let ok (key : private_key_request) =
        let rsa_key = key.key in
        Hsm.Key.add_json hsm_state ~id key.purpose ~p:rsa_key.primeP ~q:rsa_key.primeQ ~e:rsa_key.publicExponent >>= function
        | Ok () -> Wm.continue true rd
        | Error e -> Endpoint.respond_error e rd
      in
      Json.decode private_key_request_of_yojson content |>
      Endpoint.err_to_bad_request ok rd

    method! resource_exists rd =
      let id = Webmachine.Rd.lookup_path_info_exn "id" rd in
      Hsm.Key.exists hsm_state ~id >>= function
      | Ok does_exist -> Wm.continue does_exist rd
      | Error e -> Endpoint.respond_error e rd

    method! delete_resource rd =
      let id = Webmachine.Rd.lookup_path_info_exn "id" rd in
      Hsm.Key.remove hsm_state ~id >>= function
      | Ok () -> Wm.continue true rd
      | Error e -> Endpoint.respond_error e rd

    method! allowed_methods rd =
      Wm.continue [`PUT; `GET; `DELETE ] rd

    method content_types_provided rd =
      Wm.continue [ ("application/json", self#get_json) ] rd

    method content_types_accepted rd =
      Wm.continue [
        ("application/json", self#set_json)
      ] rd
  end

  class handler_public hsm_state = object(self)
    inherit Endpoint.base
    inherit !Endpoint.input_state_validated hsm_state [ `Operational ]

    method private get_pem rd =
      let id = Webmachine.Rd.lookup_path_info_exn "id" rd in
      Hsm.Key.get_pem hsm_state ~id >>= function
      | Error e -> Endpoint.respond_error e rd
      | Ok data -> Wm.continue (`String data) rd

    method! resource_exists rd =
      let id = Webmachine.Rd.lookup_path_info_exn "id" rd in
      Hsm.Key.exists hsm_state ~id >>= function
      | Ok does_exist -> Wm.continue does_exist rd
      | Error e -> Endpoint.respond_error e rd

    method! allowed_methods rd =
      Wm.continue [`GET ] rd

    method content_types_provided rd =
      Wm.continue [ ("application/x-pem-file", self#get_pem) ] rd

    method content_types_accepted rd =
      Wm.continue [ ] rd

    method! is_authorized rd =
      Access.is_authorized hsm_state rd >>= fun (auth, rd') ->
      Wm.continue auth rd'

    method! forbidden rd =
      Access.forbidden hsm_state `Administrator rd >>= fun not_an_admin ->
      Access.forbidden hsm_state `Operator rd >>= fun not_an_operator ->
      Wm.continue (not_an_admin && not_an_operator) rd
  end

  class handler_csr hsm_state = object(self)
    inherit Endpoint.base
    inherit !Endpoint.input_state_validated hsm_state [ `Operational ]

    method private csr_pem rd =
      let body = rd.Webmachine.Rd.req_body in
      Cohttp_lwt.Body.to_string body >>= fun content ->
      let id = Webmachine.Rd.lookup_path_info_exn "id" rd in
      match Json.decode_subject content with
      | Error e -> Endpoint.respond_error (Bad_request, e) rd
      | Ok subject ->
        Hsm.Key.csr_pem hsm_state ~id subject >>= function
        | Error e -> Endpoint.respond_error e rd
        | Ok csr_pem -> Wm.respond 200 ~body:(`String csr_pem) rd

    method! resource_exists rd =
      let id = Webmachine.Rd.lookup_path_info_exn "id" rd in
      Hsm.Key.exists hsm_state ~id >>= function
      | Ok does_exist -> Wm.continue does_exist rd
      | Error e -> Endpoint.respond_error e rd

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

    method! is_authorized rd =
      Access.is_authorized hsm_state rd >>= fun (auth, rd') ->
      Wm.continue auth rd'

    method! forbidden rd =
      Access.forbidden hsm_state `Administrator rd >>= fun not_an_admin ->
      Access.forbidden hsm_state `Operator rd >>= fun not_an_operator ->
      Wm.continue (not_an_admin && not_an_operator) rd
  end

  class handler_decrypt hsm_state = object(self)
    inherit Endpoint.base
    inherit !Endpoint.input_state_validated hsm_state [ `Operational ]
    inherit !Endpoint.role hsm_state `Operator

    method private decrypt rd =
      let body = rd.Webmachine.Rd.req_body in
      Cohttp_lwt.Body.to_string body >>= fun content ->
      let id = Webmachine.Rd.lookup_path_info_exn "id" rd in
      let ok (dec : decrypt) =
        Hsm.Key.decrypt hsm_state ~id dec.mode dec.encrypted >>= function
        | Ok decrypted ->
          let json = Yojson.Safe.to_string (`Assoc [ "decrypted", `String decrypted ]) in
          Wm.respond 200 ~body:(`String json) rd
        | Error e -> Endpoint.respond_error e rd
      in
      Json.decode decrypt_of_yojson content |> Endpoint.err_to_bad_request ok rd

    method! resource_exists rd =
      let id = Webmachine.Rd.lookup_path_info_exn "id" rd in
      Hsm.Key.exists hsm_state ~id >>= function
      | Ok does_exist -> Wm.continue does_exist rd
      | Error e -> Endpoint.respond_error e rd

    method !process_post rd =
      self#decrypt rd

    method! allowed_methods rd =
      Wm.continue [`POST ] rd

    method content_types_provided rd =
      Wm.continue [ ("application/json", Wm.continue `Empty) ] rd

    method content_types_accepted rd =
      Wm.continue [ ("application/json", self#decrypt) ] rd
  end

  class handler_sign hsm_state = object(self)
    inherit Endpoint.base
    inherit !Endpoint.input_state_validated hsm_state [ `Operational ]
    inherit !Endpoint.role hsm_state `Operator

    method private sign rd =
      let body = rd.Webmachine.Rd.req_body in
      Cohttp_lwt.Body.to_string body >>= fun content ->
      let id = Webmachine.Rd.lookup_path_info_exn "id" rd in
      let ok (sign : sign) =
        Hsm.Key.sign hsm_state ~id sign.mode sign.message >>= function
        | Ok signature ->
          let json = Yojson.Safe.to_string (`Assoc [ "signature", `String signature ]) in
          Wm.respond 200 ~body:(`String json) rd
        | Error e -> Endpoint.respond_error e rd
      in
      Json.decode sign_of_yojson content |> Endpoint.err_to_bad_request ok rd

    method! resource_exists rd =
      let id = Webmachine.Rd.lookup_path_info_exn "id" rd in
      Hsm.Key.exists hsm_state ~id >>= function
      | Ok does_exist -> Wm.continue does_exist rd
      | Error e -> Endpoint.respond_error e rd

    method !process_post rd =
      self#sign rd

    method! allowed_methods rd =
      Wm.continue [`POST ] rd

    method content_types_provided rd =
      Wm.continue [ ("application/json", Wm.continue `Empty) ] rd

    method content_types_accepted rd =
      Wm.continue [ ("application/json", self#sign) ] rd
  end

  class handler_cert hsm_state = object(self)
    inherit Endpoint.base
    inherit !Endpoint.input_state_validated hsm_state [ `Operational ]
    inherit !Endpoint.role_operator_get hsm_state

    method private get_cert rd =
      let id = Webmachine.Rd.lookup_path_info_exn "id" rd in
      Hsm.Key.get_cert hsm_state ~id >>= function
      | Error e -> Endpoint.respond_error e rd
      | Ok None -> Wm.respond (Cohttp.Code.code_of_status `Not_found) rd
      | Ok (Some (content_type, data)) ->
        let add_ct headers =
          Cohttp.Header.replace headers "content-type" content_type
        in
        Wm.continue (`String data) (Webmachine.Rd.with_resp_headers add_ct rd)

    method! resource_exists rd =
      let id = Webmachine.Rd.lookup_path_info_exn "id" rd in
      Hsm.Key.exists hsm_state ~id >>= function
      | Ok does_exist -> Wm.continue does_exist rd
      | Error e -> Endpoint.respond_error e rd

    method! delete_resource rd =
      let id = Webmachine.Rd.lookup_path_info_exn "id" rd in
      Hsm.Key.remove_cert hsm_state ~id >>= function
      | Ok () -> Wm.continue true rd
      | Error e -> Endpoint.respond_error e rd

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
      let id = Webmachine.Rd.lookup_path_info_exn "id" rd in
      match Cohttp.Header.get rd.req_headers "content-type" with
      | None -> Endpoint.respond_error (Bad_request, "Missing content-type header.") rd
      | Some content_type ->
        Hsm.Key.set_cert hsm_state ~id ~content_type content >>= function
        | Ok () -> Wm.respond (Cohttp.Code.code_of_status `Created) rd
        | Error e -> Endpoint.respond_error e rd
  end
end
