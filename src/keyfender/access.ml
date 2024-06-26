(* Copyright 2023 - 2023, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

open Lwt.Infix

module Make (Wm : Webmachine.S with type +'a io = 'a Lwt.t) (Hsm : Hsm.S) =
struct
  (* Headers *)
  let get_authorization headers = Cohttp.Header.get headers "Authorization"

  let get_user headers =
    match get_authorization headers with
    | None ->
        (* this can never happen, due to webmachine's control flow. We always
           set Authorization header in is_authorized, which has been called
           before. *)
        assert false
    | Some v ->
        Hsm.Nid.unsafe_of_string v (* this has already been parsed before *)

  let replace_authorization auth headers =
    Cohttp.Header.replace headers "Authorization" auth

  let decode_auth auth =
    match Astring.String.cut ~sep:"Basic " auth with
    | Some ("", b64) -> (
        match Base64.decode b64 with
        | Error (`Msg msg) ->
            Rresult.R.error_msgf "invalid base64 encoding: %s" msg
        | Ok data -> (
            match Astring.String.cut ~sep:":" data with
            | None -> Error (`Msg "invalid user:pass encoding")
            | Some (user, password) -> Ok (user, password)))
    | _ -> Error (`Msg ("invalid auth header " ^ auth))

  let is_authorized hsm_state ip rd =
    match get_authorization rd.Webmachine.Rd.req_headers with
    | None -> Wm.continue (`Basic "NetHSM") rd
    | Some auth -> (
        let err msg =
          Logs.warn (fun m -> m "is_authorized failed with message %s" msg);
          Wm.continue (`Basic "invalid authorization") rd
        in
        match decode_auth auth with
        | Ok (username, passphrase) -> (
            if not (Rate_limit.within (Hsm.now ()) ip username) then
              let cc hdr =
                Cohttp.Header.replace hdr "content-type" "application/json"
              in
              let rd' = Webmachine.Rd.with_resp_headers cc rd in
              Wm.respond
                ~body:(`String (Json.error "Too many requests"))
                429 rd'
            else
              match Hsm.Nid.of_string username with
              | Error msg -> err msg
              | Ok nid ->
                  Hsm.User.is_authenticated hsm_state nid ~passphrase
                  >>= fun auth ->
                  if auth then
                    let rd' =
                      Webmachine.Rd.with_req_headers
                        (replace_authorization username)
                        rd
                    in
                    Wm.continue `Authorized rd'
                  else (
                    Rate_limit.add (Hsm.now ()) ip username;
                    Wm.continue (`Basic "invalid authorization") rd))
        | Error (`Msg msg) -> err msg)

  let is_in_state hsm_state state = Hsm.state hsm_state = state

  let forbidden hsm_state role rd =
    let user = get_user rd.Webmachine.Rd.req_headers in
    Hsm.User.is_authorized hsm_state user role >|= fun granted -> not granted
end
