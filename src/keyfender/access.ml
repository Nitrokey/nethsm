open Lwt.Infix

module Make (Wm : Webmachine.S with type +'a io = 'a Lwt.t) (Hsm : Hsm.S) = struct
  (* Headers *)
  let get_authorization headers = Cohttp.Header.get headers "Authorization"

  let get_user headers = match get_authorization headers with
    | None ->
      (* this can never happen, due to webmachine's control flow. We always
         set Authorization header in is_authorized, which has been called
         before. *)
      assert false
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

  let requests : (Ipaddr.V4.t, Ptime.t list) Hashtbl.t = Hashtbl.create 7

  let max_requests_per_second = 10

  let within_rate_limit ip =
    match Hashtbl.find_opt requests ip with
    | None -> Hashtbl.add requests ip [ Hsm.now () ] ; true
    | Some last_requests ->
      let one_second_ago =
        let one_second = Ptime.Span.of_int_s 1 in
        match Ptime.sub_span (Hsm.now ()) one_second with
        | Some ts -> ts
        | None -> Ptime.epoch (* clamped to 0 *)
      in
      let requests' = List.filter (Ptime.is_later ~than:one_second_ago) last_requests in
      let result = List.length requests' <= max_requests_per_second in
      Hashtbl.replace requests ip (Hsm.now () :: requests');
      result

  let reset_rate_limit ip = Hashtbl.remove requests ip

  let is_authorized hsm_state ip rd =
    match get_authorization rd.Webmachine.Rd.req_headers with
    | None -> Wm.continue (`Basic "NitroHSM") rd
    | Some auth ->
      match decode_auth auth with
      | Ok (username, passphrase) ->
        if not (within_rate_limit ip) then
          Wm.respond ~body:(`String "Too many requests") 429 rd
        else
          Hsm.User.is_authenticated hsm_state ~username ~passphrase >>= fun auth ->
          if auth then begin
            reset_rate_limit ip;
            let rd' = Webmachine.Rd.with_req_headers (replace_authorization username) rd in
            Wm.continue `Authorized rd'
          end else
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
