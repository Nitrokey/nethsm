open Lwt.Infix

module Make (Wm : Webmachine.S with type +'a io = 'a Lwt.t) (Hsm : Hsm.S) = struct
  module Access = Access.Make(Hsm)
  module Utils = Wm_utils.Make(Wm)(Hsm)

  type rsa_key = { primeP : string ; primeQ : string ; publicExponent : string } [@@deriving yojson]
  type private_key_request = { purpose: Hsm.Keys.purpose ; algorithm: string ; key : rsa_key }[@@deriving yojson]

  type decrypt = { mode : Hsm.Keys.decrypt_mode ; encrypted : string }[@@deriving yojson]

  class handler_keys hsm_state = object(self)
    inherit [Cohttp_lwt.Body.t] Wm.resource

    method private get_json rd =
      Hsm.Keys.list hsm_state >>= function
      | Error e -> Utils.respond_error e rd
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
        Hsm.Keys.add_json hsm_state ~id key.purpose ~p:rsa_key.primeP ~q:rsa_key.primeQ ~e:rsa_key.publicExponent >>= function
        | Ok () -> Wm.continue true rd
        | Error e -> Utils.respond_error e rd
      in
      Json.decode private_key_request_of_yojson content |> 
      Utils.err_to_bad_request ok rd

    method private set_pem rd =
      let body = rd.Webmachine.Rd.req_body in
      Cohttp_lwt.Body.to_string body >>= fun content ->
      let id = match Cohttp.Header.get rd.req_headers "new_id" with
      | None -> assert false | Some path -> path in
      Hsm.Keys.add_pem hsm_state ~id Hsm.Keys.Encrypt (*TODO*) content >>= function
      | Ok () -> Wm.continue true rd
      | Error e -> Utils.respond_error e rd

    method! post_is_create rd =
      Wm.continue true rd

    method! create_path rd =
      let path = Hsm.generate_id () in
      let rd' = { rd with req_headers = Cohttp.Header.add rd.req_headers "new_id" path } in
      Wm.continue path rd'
      
    method! allowed_methods rd =
      Wm.continue [`POST; `GET ] rd

    method! known_methods rd =
      Wm.continue [`POST; `GET ] rd

    method content_types_provided rd =
      Wm.continue [ ("application/json", self#get_json) ] rd

    method content_types_accepted rd =
      Wm.continue [
        ("application/json", self#set_json) ;
        ("application/x-pem-file", self#set_pem)
      ] rd

    (* we use this not for the service, but to check the internal state before processing requests *)
    method! service_available rd =
      if Access.is_in_state hsm_state `Operational
      then Wm.continue true rd
      else Wm.respond (Cohttp.Code.code_of_status `Precondition_failed) rd

    method! is_authorized rd =
      Access.is_authorized hsm_state rd >>= fun (auth, rd') ->
      Wm.continue auth rd'

    method! forbidden rd =
      Access.forbidden hsm_state `Administrator rd >>= function
      | true when rd.meth = `GET -> (* no admin - only get allowed for operator *)
        Access.forbidden hsm_state `Operator rd >>= fun not_an_operator ->
        Wm.continue not_an_operator rd
      | not_an_admin -> Wm.continue not_an_admin rd
  end

  type generate_request = { purpose: Hsm.Keys.purpose ; algorithm : string ; length : int ; id : (string [@default ""]) } [@@deriving yojson] 

  class handler_keys_generate hsm_state = object(self)
    inherit [Cohttp_lwt.Body.t] Wm.resource

    method private set_json rd =
      let body = rd.Webmachine.Rd.req_body in
      Cohttp_lwt.Body.to_string body >>= fun content ->
      let ok (key : generate_request) =
        let id = match key.id, Cohttp.Header.get rd.req_headers "new_id" with
        | "", Some path -> path 
        | "", None -> assert false 
        | id, _ -> id
        in
        Hsm.Keys.generate hsm_state ~id key.purpose ~length:key.length >>= function
        | Ok () -> Wm.continue true rd
        | Error e -> Utils.respond_error e rd
      in
      Json.decode generate_request_of_yojson content |> 
      Utils.err_to_bad_request ok rd

    method! post_is_create rd =
      Wm.continue true rd

    method! create_path rd =
      let path = Hsm.generate_id () in
      let rd' = { rd with req_headers = Cohttp.Header.add rd.req_headers "new_id" path } in
      Wm.continue path rd'
 
    method! allowed_methods rd =
      Wm.continue [`POST] rd

    method! known_methods rd =
      Wm.continue [`POST] rd

    method private empty rd = Wm.continue `Empty rd

    method content_types_provided rd =
      Wm.continue [ ("application/json", self#empty) ] rd

    method content_types_accepted rd =
      Wm.continue [
        ("application/json", self#set_json)
      ] rd

    (* we use this not for the service, but to check the internal state before processing requests *)
    method! service_available rd =
      if Access.is_in_state hsm_state `Operational
      then Wm.continue true rd
      else Wm.respond (Cohttp.Code.code_of_status `Precondition_failed) rd

    method! is_authorized rd =
      Access.is_authorized hsm_state rd >>= fun (auth, rd') ->
      Wm.continue auth rd'

    method! forbidden rd =
      Access.forbidden hsm_state `Administrator rd >>= fun not_an_admin ->
      Wm.continue not_an_admin rd
  end

  class handler hsm_state = object(self)
    inherit [Cohttp_lwt.Body.t] Wm.resource

    method private get_json rd =
      let id = Webmachine.Rd.lookup_path_info_exn "id" rd in
      Hsm.Keys.get_json ~id hsm_state >>= function
      | Error e -> Utils.respond_error e rd
      | Ok public_key ->
        let body = Yojson.Safe.to_string @@ Hsm.Keys.publicKey_to_yojson public_key in
        Wm.continue (`String body) rd

    method private set_json rd =
      let body = rd.Webmachine.Rd.req_body in
      Cohttp_lwt.Body.to_string body >>= fun content ->
      let id = Webmachine.Rd.lookup_path_info_exn "id" rd in
      let ok (key : private_key_request) =
        let rsa_key = key.key in
        Hsm.Keys.add_json hsm_state ~id key.purpose ~p:rsa_key.primeP ~q:rsa_key.primeQ ~e:rsa_key.publicExponent >>= function
        | Ok () -> Wm.continue true rd
        | Error e -> Utils.respond_error e rd
      in
      Json.decode private_key_request_of_yojson content |> 
      Utils.err_to_bad_request ok rd

    method! resource_exists rd =
      let id = Webmachine.Rd.lookup_path_info_exn "id" rd in
      Hsm.Keys.exists hsm_state ~id >>= function
      | Ok does_exist -> Wm.continue does_exist rd
      | Error e -> Utils.respond_error e rd

    method! delete_resource rd =
      let id = Webmachine.Rd.lookup_path_info_exn "id" rd in
      Hsm.Keys.remove hsm_state ~id >>= function
      | Ok () -> Wm.continue true rd
      | Error e -> Utils.respond_error e rd

    method! allowed_methods rd =
      Wm.continue [`PUT; `GET; `DELETE ] rd

    method! known_methods rd =
      Wm.continue [`PUT; `GET; `DELETE ] rd

    method content_types_provided rd =
      Wm.continue [ ("application/json", self#get_json) ] rd

    method content_types_accepted rd =
      Wm.continue [
        ("application/json", self#set_json)
      ] rd

    (* we use this not for the service, but to check the internal state before processing requests *)
    method! service_available rd =
      if Access.is_in_state hsm_state `Operational
      then Wm.continue true rd
      else Wm.respond (Cohttp.Code.code_of_status `Precondition_failed) rd

    method! is_authorized rd =
      Access.is_authorized hsm_state rd >>= fun (auth, rd') ->
      Wm.continue auth rd'

    method! forbidden rd =
      Access.forbidden hsm_state `Administrator rd >>= function
      | true when rd.meth = `GET -> 
        Access.forbidden hsm_state `Operator rd >>= fun not_an_operator ->
        Wm.continue not_an_operator rd
      | not_an_admin -> Wm.continue not_an_admin rd
  end

  class handler_public hsm_state = object(self)
    inherit [Cohttp_lwt.Body.t] Wm.resource

    method private get_pem rd =
      let id = Webmachine.Rd.lookup_path_info_exn "id" rd in
      Hsm.Keys.get_pem hsm_state ~id >>= function
      | Error e -> Utils.respond_error e rd
      | Ok data -> Wm.continue (`String data) rd

    method! resource_exists rd =
      let id = Webmachine.Rd.lookup_path_info_exn "id" rd in
      Hsm.Keys.exists hsm_state ~id >>= function
      | Ok does_exist -> Wm.continue does_exist rd
      | Error e -> Utils.respond_error e rd

    method! allowed_methods rd =
      Wm.continue [`GET ] rd

    method! known_methods rd =
      Wm.continue [`GET ] rd

    method content_types_provided rd =
      Wm.continue [ ("application/x-pem-file", self#get_pem) ] rd

    method content_types_accepted rd =
      Wm.continue [ ] rd

    (* we use this not for the service, but to check the internal state before processing requests *)
    method! service_available rd =
      if Access.is_in_state hsm_state `Operational
      then Wm.continue true rd
      else Wm.respond (Cohttp.Code.code_of_status `Precondition_failed) rd

    method! is_authorized rd =
      Access.is_authorized hsm_state rd >>= fun (auth, rd') ->
      Wm.continue auth rd'

    method! forbidden rd =
      Access.forbidden hsm_state `Administrator rd >>= fun not_an_admin ->
      Access.forbidden hsm_state `Operator rd >>= fun not_an_operator ->
      Wm.continue (not_an_admin && not_an_operator) rd
  end
 
  class handler_csr hsm_state = object(self)
    inherit [Cohttp_lwt.Body.t] Wm.resource

    method private csr_pem rd =
      let body = rd.Webmachine.Rd.req_body in
      Cohttp_lwt.Body.to_string body >>= fun content ->
      let id = Webmachine.Rd.lookup_path_info_exn "id" rd in
      match Json.decode_subject content with
      | Error e -> Utils.respond_error (Bad_request, e) rd
      | Ok subject ->
        Hsm.Keys.csr_pem hsm_state ~id subject >>= function
        | Error e -> Utils.respond_error e rd
        | Ok csr_pem -> Wm.respond 200 ~body:(`String csr_pem) rd

    method! resource_exists rd =
      let id = Webmachine.Rd.lookup_path_info_exn "id" rd in
      Hsm.Keys.exists hsm_state ~id >>= function
      | Ok does_exist -> Wm.continue does_exist rd
      | Error e -> Utils.respond_error e rd

    method !process_post rd =
      self#csr_pem rd

    method! allowed_methods rd =
      Wm.continue [`POST ] rd

    method! known_methods rd =
      Wm.continue [`POST ] rd

    method content_types_provided rd =
      Wm.continue [ ("application/json", Wm.continue `Empty) ] rd

    method content_types_accepted rd =
      Wm.continue [
        ("application/x-pem-file", self#csr_pem)
      ] rd

    (* we use this not for the service, but to check the internal state before processing requests *)
    method! service_available rd =
      if Access.is_in_state hsm_state `Operational
      then Wm.continue true rd
      else Wm.respond (Cohttp.Code.code_of_status `Precondition_failed) rd

    method! is_authorized rd =
      Access.is_authorized hsm_state rd >>= fun (auth, rd') ->
      Wm.continue auth rd'

    method! forbidden rd =
      Access.forbidden hsm_state `Administrator rd >>= fun not_an_admin ->
      Access.forbidden hsm_state `Operator rd >>= fun not_an_operator ->
      Wm.continue (not_an_admin && not_an_operator) rd
  end

  class handler_decrypt hsm_state = object(self)
    inherit [Cohttp_lwt.Body.t] Wm.resource

    method private decrypt rd =
      let body = rd.Webmachine.Rd.req_body in
      Cohttp_lwt.Body.to_string body >>= fun content ->
      let id = Webmachine.Rd.lookup_path_info_exn "id" rd in
      let ok (dec : decrypt) =
        Hsm.Keys.decrypt hsm_state ~id dec.mode dec.encrypted >>= function
        | Ok decrypted ->
          let json = Yojson.Safe.to_string (`Assoc [ "decrypted", `String decrypted ]) in
          Wm.respond 200 ~body:(`String json) rd
        | Error e -> Utils.respond_error e rd
      in
      Json.decode decrypt_of_yojson content |> Utils.err_to_bad_request ok rd

    method! resource_exists rd =
      let id = Webmachine.Rd.lookup_path_info_exn "id" rd in
      Hsm.Keys.exists hsm_state ~id >>= function
      | Ok does_exist -> Wm.continue does_exist rd
      | Error e -> Utils.respond_error e rd

    method !process_post rd =
      self#decrypt rd

    method! allowed_methods rd =
      Wm.continue [`POST ] rd

    method! known_methods rd =
      Wm.continue [`POST ] rd

    method content_types_provided rd =
      Wm.continue [ ("application/json", Wm.continue `Empty) ] rd

    method content_types_accepted rd =
      Wm.continue [
        ("application/json", self#decrypt)
      ] rd

    (* we use this not for the service, but to check the internal state before processing requests *)
    method! service_available rd =
      if Access.is_in_state hsm_state `Operational
      then Wm.continue true rd
      else Wm.respond (Cohttp.Code.code_of_status `Precondition_failed) rd

    method! is_authorized rd =
      Access.is_authorized hsm_state rd >>= fun (auth, rd') ->
      Wm.continue auth rd'

    method! forbidden rd =
      Access.forbidden hsm_state `Operator rd >>= fun not_an_operator ->
      Wm.continue not_an_operator rd
  end

  class handler_sign hsm_state = object(self)
    inherit [Cohttp_lwt.Body.t] Wm.resource

    method private get_json rd =
      Hsm.User.list hsm_state >>= function
      | Error e -> Utils.respond_error e rd
      | Ok users ->
        let items = List.map (fun user -> `Assoc [ "user", `String user ]) users in
        let body = Yojson.Safe.to_string (`List items) in
        Wm.continue (`String body) rd

    method private set_json rd =
      let body = rd.Webmachine.Rd.req_body in
      Cohttp_lwt.Body.to_string body >>= fun _content ->
      assert false

    method! resource_exists rd =
      let id = Webmachine.Rd.lookup_path_info_exn "id" rd in
      Hsm.Keys.exists hsm_state ~id >>= function
      | Ok does_exist -> Wm.continue does_exist rd
      | Error e -> Utils.respond_error e rd

    method !process_post rd =
      self#set_json rd

    method! allowed_methods rd =
      Wm.continue [`POST; `GET ] rd

    method! known_methods rd =
      Wm.continue [`POST; `GET ] rd

    method content_types_provided rd =
      Wm.continue [ ("application/json", self#get_json) ] rd

    method content_types_accepted rd =
      Wm.continue [
        ("application/json", self#set_json)
      ] rd

    (* we use this not for the service, but to check the internal state before processing requests *)
    method! service_available rd =
      if Access.is_in_state hsm_state `Operational
      then Wm.continue true rd
      else Wm.respond (Cohttp.Code.code_of_status `Precondition_failed) rd

    method! is_authorized rd =
      Access.is_authorized hsm_state rd >>= fun (auth, rd') ->
      Wm.continue auth rd'

    method! forbidden rd =
      Access.forbidden hsm_state `Administrator rd >>= fun not_an_admin ->
      Wm.continue not_an_admin rd
  end

  class handler_cert hsm_state = object(self)
    inherit [Cohttp_lwt.Body.t] Wm.resource

    method private get_json rd =
      Hsm.User.list hsm_state >>= function
      | Error e -> Utils.respond_error e rd
      | Ok users ->
        let items = List.map (fun user -> `Assoc [ "user", `String user ]) users in
        let body = Yojson.Safe.to_string (`List items) in
        Wm.continue (`String body) rd

    method private set_json rd =
      let body = rd.Webmachine.Rd.req_body in
      Cohttp_lwt.Body.to_string body >>= fun _content ->
      assert false

    method! resource_exists rd =
      let id = Webmachine.Rd.lookup_path_info_exn "id" rd in
      Hsm.Keys.exists hsm_state ~id >>= function
      | Ok does_exist -> Wm.continue does_exist rd
      | Error e -> Utils.respond_error e rd

    method !process_post rd =
      self#set_json rd

    method! allowed_methods rd =
      Wm.continue [`POST; `GET ] rd

    method! known_methods rd =
      Wm.continue [`POST; `GET ] rd

    method content_types_provided rd =
      Wm.continue [ ("application/json", self#get_json) ] rd

    method content_types_accepted rd =
      Wm.continue [
        ("application/json", self#set_json)
      ] rd

    (* we use this not for the service, but to check the internal state before processing requests *)
    method! service_available rd =
      if Access.is_in_state hsm_state `Operational
      then Wm.continue true rd
      else Wm.respond (Cohttp.Code.code_of_status `Precondition_failed) rd

    method! is_authorized rd =
      Access.is_authorized hsm_state rd >>= fun (auth, rd') ->
      Wm.continue auth rd'

    method! forbidden rd =
      Access.forbidden hsm_state `Administrator rd >>= fun not_an_admin ->
      Wm.continue not_an_admin rd
  end

end
