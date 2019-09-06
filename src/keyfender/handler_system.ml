(* Headers *)
let get_authorization headers = Cohttp.Header.get headers "Authorization"

let get_user headers = match get_authorization headers with
  | None -> assert false
  | Some v -> v

let replace_authorization auth headers =
  Cohttp.Header.replace headers "Authorization" auth

let decode_auth v =
  match Astring.String.cut ~sep:"Basic " v with
  | Some ("", b64) ->
    begin match Nocrypto.Base64.decode (Cstruct.of_string b64) with
      | None -> Error (`Msg ("invalid base64 encoding " ^ b64))
      | Some data -> match Astring.String.cut ~sep:":" (Cstruct.to_string data) with
        | None -> Error (`Msg ("invalid user:pass encoding" ^ Cstruct.to_string data))
        | Some (user, password) -> Ok (user, password)
    end
  | _ -> Error (`Msg ("invalid auth header " ^ v))


module Make (Wm : Webmachine.S with type +'a io = 'a Lwt.t) = struct

  class handler hsm_state = object(self)
    inherit [Cohttp_lwt.Body.t] Wm.resource

    method private system_info rd =
      match Webmachine.Rd.lookup_path_info "ep" rd with
      | Some "info" -> 
        let open Hsm in
        let json = Yojson.Safe.to_string (system_info_to_yojson @@ system_info hsm_state) in
        Wm.continue (`String json) rd
      | _ -> Wm.respond (Cohttp.Code.code_of_status `Not_found) rd
       
    (* TODO we get 500 instead of 200 when we post to reset etc *)
    method private system rd =
      match Webmachine.Rd.lookup_path_info "ep" rd with
      | Some "reboot" -> 
        Hsm.reboot () ;
        Wm.continue true rd
      | Some "shutdown" -> 
        Hsm.shutdown () ;
        Wm.continue true rd
      | Some "reset" ->
        Hsm.reset () ;
        Wm.continue true rd
      | Some "update" ->  Wm.respond (Cohttp.Code.code_of_status `Not_found) rd
      | Some "backup" ->  Wm.respond (Cohttp.Code.code_of_status `Not_found) rd
      | Some "restore" -> Wm.respond (Cohttp.Code.code_of_status `Not_found) rd
      | _ -> Wm.respond (Cohttp.Code.code_of_status `Not_found) rd

    method! is_authorized rd =
      match get_authorization rd.Webmachine.Rd.req_headers with
      | None -> Wm.continue (`Basic "NitroHSM") rd
      | Some auth -> 
        match decode_auth auth with
        | Ok (username, password) -> 
          if Hsm.is_authenticated hsm_state ~username ~password
          then 
            let rd' = Webmachine.Rd.with_req_headers (replace_authorization username) rd in
            Wm.continue `Authorized rd'
          else
            Wm.continue (`Basic "invalid authorization") rd
        | Error (`Msg msg) ->
          Logs.warn (fun m -> m "is_authorized failed with header value %s and message %s" auth msg);
          Wm.continue (`Basic "invalid authorization") rd

    method! forbidden rd =
      let user = get_user rd.Webmachine.Rd.req_headers in
      let granted = Hsm.is_authorized hsm_state user Hsm.Administrator in
      Wm.continue (not granted) rd

    method !process_post rd =
      Wm.continue true rd 

    method !allowed_methods rd =
      Wm.continue [ `GET ; `POST ] rd
 
    method content_types_provided rd =
      Wm.continue [ ("application/json", self#system_info) ] rd

    method content_types_accepted rd =
      Wm.continue [ ("application/json", self#system) ] rd

  end

end
