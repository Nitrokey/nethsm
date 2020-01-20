open Lwt.Infix

module Make (Wm : Webmachine.S with type +'a io = 'a Lwt.t) (Hsm : Hsm.S) = struct
  (* Headers *)
  let get_authorization headers = Cohttp.Header.get headers "Authorization"

  let get_user headers = match get_authorization headers with
    | None -> assert false
    | Some v -> v

  let replace_authorization auth headers =
    Cohttp.Header.replace headers "Authorization" auth

  let decode_auth auth =
    match Astring.String.cut ~sep:"Basic " auth with
    | Some ("", b64) ->
      begin match Nocrypto.Base64.decode (Cstruct.of_string b64) with
        | None -> Error (`Msg ("invalid base64 encoding " ^ b64))
        | Some data -> match Astring.String.cut ~sep:":" (Cstruct.to_string data) with
          | None -> Error (`Msg ("invalid user:pass encoding" ^ Cstruct.to_string data))
          | Some (user, password) -> Ok (user, password)
      end
    | _ -> Error (`Msg ("invalid auth header " ^ auth))

  let is_authorized hsm_state rd =
    match get_authorization rd.Webmachine.Rd.req_headers with
    | None -> Wm.continue (`Basic "NitroHSM") rd
    | Some auth ->
      match decode_auth auth with
      | Ok (username, passphrase) ->
        (* data structure: ip -> (request, timestamp) ; sliding window *)
        (* check whether rate limit is reached *)
        if (* rate limit exceeded *) false then
          Wm.respond ~body:(`String "Too many requests") 429 rd
        else
          Hsm.User.is_authenticated hsm_state ~username ~passphrase >>= fun auth ->
          if auth then
            let rd' = Webmachine.Rd.with_req_headers (replace_authorization username) rd in
            Wm.continue `Authorized rd'
          else
            Wm.continue (`Basic "invalid authorization") rd
      | Error (`Msg msg) ->
        Logs.warn (fun m -> m "is_authorized failed with header value %s and message %s" auth msg);
        Wm.continue (`Basic "invalid authorization") rd

  let is_in_state hsm_state state =
    Hsm.state hsm_state = state

  let forbidden hsm_state role rd =
    let user = get_user rd.Webmachine.Rd.req_headers in
    Hsm.User.is_authorized hsm_state user role >|= fun granted ->
    not granted
end
