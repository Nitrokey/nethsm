open Lwt.Infix

module Make (Wm : Webmachine.S with type +'a io = 'a Lwt.t) (Hsm : Hsm.S) = struct
  module Access = Access.Make(Hsm)
  module Utils = Wm_utils.Make(Wm)(Hsm)

  type rsa_key = { primeP : string ; primeQ : string ; publicExponent : string } [@@deriving yojson]
  type private_key_request = { purpose: Hsm.Keys.purpose ; algorithm: string ; key : rsa_key }[@@deriving yojson]

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
      match Webmachine.Rd.lookup_path_info "id" rd with
      | None -> Wm.continue `Empty rd
      | Some key_id ->
        Hsm.Keys.get_json ~id:key_id hsm_state >>= function
        | Error e -> Utils.respond_error e rd
        | Ok public_key ->
          let body = Yojson.Safe.to_string @@ Hsm.Keys.publicKey_to_yojson public_key in
          Wm.continue (`String body) rd

    method private set_json rd =
      let body = rd.Webmachine.Rd.req_body in
      Cohttp_lwt.Body.to_string body >>= fun content ->
      match Webmachine.Rd.lookup_path_info "id" rd with
      | None -> Wm.continue false rd
      | Some key_id ->
        let ok (key : private_key_request) =
          let rsa_key = key.key in
          Hsm.Keys.add_json hsm_state ~id:key_id key.purpose ~p:rsa_key.primeP ~q:rsa_key.primeQ ~e:rsa_key.publicExponent >>= function
          | Ok () -> Wm.continue true rd
          | Error e -> Utils.respond_error e rd
        in
        Json.decode private_key_request_of_yojson content |> 
        Utils.err_to_bad_request ok rd

    method! resource_exists rd =
      match Webmachine.Rd.lookup_path_info "id" rd with
      | None -> Wm.continue false rd
      | Some key_id -> Hsm.Keys.exists hsm_state ~id:key_id >>= function
        | Ok does_exist -> Wm.continue does_exist rd
        | Error e -> Utils.respond_error e rd

    method! delete_resource rd =
      match Webmachine.Rd.lookup_path_info "id" rd with
      | None -> Wm.continue false rd
      | Some key_id -> Hsm.Keys.remove hsm_state ~id:key_id >>= function
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
 
  class handler_csr hsm_state = object(self)
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

  class handler_decrypt hsm_state = object(self)
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
