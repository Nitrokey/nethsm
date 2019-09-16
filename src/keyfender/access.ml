open Lwt.Infix

module Make (Hsm : Hsm.S) = struct
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
    | None -> Lwt.return (`Basic "NitroHSM", rd)
    | Some auth ->
      match decode_auth auth with
      | Ok (username, passphrase) ->
        Hsm.is_authenticated hsm_state ~username ~passphrase >|= fun auth ->
        if auth then
          let rd' = Webmachine.Rd.with_req_headers (replace_authorization username) rd in
          `Authorized, rd'
        else
          `Basic "invalid authorization", rd
      | Error (`Msg msg) ->
        Logs.warn (fun m -> m "is_authorized failed with header value %s and message %s" auth msg);
        Lwt.return (`Basic "invalid authorization", rd)

  let is_in_state hsm_state state =
    Hsm.state hsm_state = state

  let forbidden hsm_state role rd =
    let user = get_user rd.Webmachine.Rd.req_headers in
    Hsm.is_authorized hsm_state user role >|= fun granted ->
    not granted
end
