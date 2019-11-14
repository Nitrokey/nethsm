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

  class handler hsm_state = object(self)
    inherit [Cohttp_lwt.Body.t] Wm.resource

    method private get_json rd =
      match Webmachine.Rd.lookup_path_info "id" rd with
      | None -> Wm.continue `Empty rd
      | Some user_id ->
          Hsm.User.get hsm_state user_id >>= function
          | Error e -> Utils.respond_error e rd
          | Ok user ->
            let user_reply = { realName = user.name ; role = user.role } in
            let body = Yojson.Safe.to_string (user_reply_to_yojson user_reply) in
            Wm.continue (`String body) rd

    method private set_json rd =
      let uri = rd.Webmachine.Rd.uri in
      let path = Uri.path uri in
      let body = rd.Webmachine.Rd.req_body in
      Cohttp_lwt.Body.to_string body >>= fun content ->
      match Astring.String.cuts ~sep:"/" path with
       | [ userid ] ->
          let ok (user : user_req) =
            Hsm.User.add ~id:userid hsm_state ~role:user.role ~name:user.realName ~passphrase:user.passphrase >>= function
            | Ok () -> Wm.continue true rd
            | Error e -> Utils.respond_error e rd
          in
          decode_user content |> Utils.err_to_bad_request ok rd
       | [ _userid ; "passphrase" ] -> Wm.continue true rd
       | _ -> Wm.continue false rd

    method! resource_exists rd =
      match Webmachine.Rd.lookup_path_info "id" rd with
      | None -> Wm.continue false rd
      | Some user_id -> Hsm.User.exists hsm_state user_id >>= function
        | Ok does_exist -> Wm.continue does_exist rd
        | Error e -> Utils.respond_error e rd

    method! allowed_methods rd =
      Wm.continue [`PUT; `GET; `DELETE ] rd

    method! known_methods rd =
      Wm.continue [`PUT; `GET; `DELETE ] rd

    method private create_user rd = 
      Wm.continue true rd

    method content_types_provided rd =
      Wm.continue [ ("application/json", self#get_json) ] rd

    method content_types_accepted rd =
      Wm.continue [
        ("application/json", self#set_json)
      ] rd

    method! delete_resource rd =
      match Webmachine.Rd.lookup_path_info "id" rd with
      | None -> Wm.continue false rd
      | Some user_id -> Hsm.User.remove hsm_state user_id >>= function
        | Ok () -> Wm.continue true rd
        | Error e -> Utils.respond_error e rd

    (* we use this not for the service, but to check the internal state before processing requests *)
    method! service_available rd =
      if Access.is_in_state hsm_state `Operational
      then Wm.continue true rd
      else Wm.respond (Cohttp.Code.code_of_status `Precondition_failed) rd

    method! is_authorized rd =
      Access.is_authorized hsm_state rd >>= fun (auth, rd') ->
      Wm.continue auth rd'

    method! forbidden rd =
      (* R-Administrator may GET/PUT/DELETE/POST everything *)
      (* /users/:UserID and /users/:UserID/passphrase *)
      Access.forbidden hsm_state `Administrator rd >>= fun not_an_admin ->
      (if not_an_admin then
         (* R-Operator may GET (all!) users, and POST their own passphrase *)
         let uri = rd.Webmachine.Rd.uri in
         let path = Uri.path uri in
         let segments = Astring.String.cuts ~sep:"/" path in
         let user, passphrase = match segments with
           | [ a ; b ] -> a, b
           | _ -> "", ""
         in
         (* TODO do we need to decouple userid from username? *)
         match rd.Webmachine.Rd.meth, user, passphrase with
         | `GET, _, _ -> Access.forbidden hsm_state `Operator rd
         | `POST, userid, "passphrase" ->
           if Access.get_user rd.Webmachine.Rd.req_headers = userid then
             Access.forbidden hsm_state `Operator rd
           else
             Lwt.return not_an_admin
         | _ -> Lwt.return not_an_admin
       else
         Lwt.return not_an_admin) >>= fun forbidden ->
      Wm.continue forbidden rd
  end

end
