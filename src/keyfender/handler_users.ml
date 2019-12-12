open Lwt.Infix

module Make (Wm : Webmachine.S with type +'a io = 'a Lwt.t) (Hsm : Hsm.S) = struct

  type user_req = {
      realName : string ;
      role : Hsm.User.role ;
      passphrase : string ;
  }[@@deriving yojson]

  let decode_user content =
    let open Rresult.R.Infix in
    Json.decode user_req_of_yojson content >>= fun user ->
    Json.nonempty ~name:"passphrase" user.passphrase >>| fun () ->
    user

  type user_reply = {
      realName : string ;
      role : Hsm.User.role ;
  }[@@deriving yojson]

  module Access = Access.Make(Hsm)
  module Utils = Wm_utils.Make(Wm)(Hsm)
  module Endpoint = Endpoint.Make(Wm)(Hsm)

  class handler_users hsm_state = object(self)
    inherit Endpoint.base
    inherit !Endpoint.input_state_validated hsm_state [ `Operational ]
    inherit !Endpoint.role hsm_state `Administrator

    method private get_json rd =
      Hsm.User.list hsm_state >>= function
      | Error e -> Utils.respond_error e rd
      | Ok users ->
        let items = List.map (fun user -> `Assoc [ "user", `String user ]) users in
        let body = Yojson.Safe.to_string (`List items) in
        Wm.continue (`String body) rd

    method private set_json rd =
      let body = rd.Webmachine.Rd.req_body in
      Cohttp_lwt.Body.to_string body >>= fun content ->
      let ok (user : user_req) =
        let id = match Cohttp.Header.get rd.req_headers "new_id" with
        | None -> assert false | Some path -> path in
        Hsm.User.add hsm_state ~id ~role:user.role ~name:user.realName ~passphrase:user.passphrase >>= function
        | Ok () -> Wm.continue true rd
        | Error e -> Utils.respond_error e rd
      in
      decode_user content |> Utils.err_to_bad_request ok rd

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
      Wm.continue [ ("application/json", self#set_json) ] rd
  end


  class handler hsm_state = object(self)
    inherit Endpoint.base
    inherit !Endpoint.input_state_validated hsm_state [ `Operational ]
    inherit !Endpoint.role_operator_get hsm_state

    method private get_json rd =
      let id = Webmachine.Rd.lookup_path_info_exn "id" rd in
      Hsm.User.get hsm_state ~id >>= function
      | Error e -> Utils.respond_error e rd
      | Ok (name, role) ->
        let user_reply = { realName = name ; role } in
        let body = Yojson.Safe.to_string (user_reply_to_yojson user_reply) in
        Wm.continue (`String body) rd

    method private set_json rd =
      let body = rd.Webmachine.Rd.req_body in
      Cohttp_lwt.Body.to_string body >>= fun content ->
      let id = Webmachine.Rd.lookup_path_info_exn "id" rd in
      let ok (user : user_req) =
        Hsm.User.add ~id hsm_state ~role:user.role ~name:user.realName ~passphrase:user.passphrase >>= function
        | Ok _id -> Wm.continue true rd
        | Error e -> Utils.respond_error e rd
      in
      decode_user content |> Utils.err_to_bad_request ok rd

    method! resource_exists rd =
      let id = Webmachine.Rd.lookup_path_info_exn "id" rd in
      Hsm.User.exists hsm_state ~id >>= function
      | Ok does_exist -> Wm.continue does_exist rd
      | Error e -> Utils.respond_error e rd

    method! allowed_methods rd =
      Wm.continue [`PUT; `GET; `DELETE ] rd

    method content_types_provided rd =
      Wm.continue [ ("application/json", self#get_json) ] rd

    method content_types_accepted rd =
      Wm.continue [
        ("application/json", self#set_json)
      ] rd

    method! delete_resource rd =
      let id = Webmachine.Rd.lookup_path_info_exn "id" rd in
      Hsm.User.remove hsm_state ~id >>= function
      | Ok () -> Wm.continue true rd
      | Error e -> Utils.respond_error e rd
  end

  class handler_passphrase hsm_state = object(self)
    inherit Endpoint.base
    inherit !Endpoint.input_state_validated hsm_state [ `Operational ]

    method private set_json rd =
      let body = rd.Webmachine.Rd.req_body in
      Cohttp_lwt.Body.to_string body >>= fun content ->
      let id = Webmachine.Rd.lookup_path_info_exn "id" rd in
      let ok passphrase =
        Hsm.User.set_passphrase hsm_state ~id ~passphrase >>= function
        | Ok () -> Wm.continue true rd
        | Error e -> Utils.respond_error e rd
      in
      Json.decode_passphrase content |> Utils.err_to_bad_request ok rd

    method! resource_exists rd =
      let id = Webmachine.Rd.lookup_path_info_exn "id" rd in
      Hsm.User.exists hsm_state ~id >>= function
      | Ok does_exist -> Wm.continue does_exist rd
      | Error e -> Utils.respond_error e rd

    method! allowed_methods rd =
      Wm.continue [`POST] rd

    method content_types_provided rd =
      Wm.continue [ ("application/json", Wm.continue `Empty) ] rd

    method content_types_accepted rd =
      Wm.continue [ ("application/json", self#set_json) ] rd

    method !process_post rd =
      self#set_json rd

    method! is_authorized rd =
      Access.is_authorized hsm_state rd >>= fun (auth, rd') ->
      Wm.continue auth rd'

    method! forbidden rd =
      (* R-Administrator may GET/PUT/DELETE/POST everything *)
      (* /users/:UserID and /users/:UserID/passphrase *)
      Access.forbidden hsm_state `Administrator rd >>= fun not_an_admin ->
      begin
        (* R-Operator may GET (all!) users, and POST their own passphrase *)
        let id = Webmachine.Rd.lookup_path_info_exn "id" rd in
        if Access.get_user rd.Webmachine.Rd.req_headers = id then
          Access.forbidden hsm_state `Operator rd
        else
          Lwt.return not_an_admin
      end >>= fun not_an_operator ->
      Wm.continue (not_an_admin && not_an_operator) rd
  end
end
