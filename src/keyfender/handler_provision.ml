open Lwt.Infix

type req_body = { unlockPassphrase : string ; adminPassphrase : string ; time : string }[@@deriving yojson]

let nonempty s =
  if String.length s == 0
  then Error `Bad_request
  else Ok ()
 
let try_parse_json content = 
  try 
    Ok (Yojson.Safe.from_string content)
  with Yojson.Safe.Finally _ -> Error `Bad_request

let parse_req_body json =
  Rresult.R.reword_error (fun _ -> `Bad_request) @@ req_body_of_yojson json
 
let decode_json content =
  let open Rresult.R.Infix in
  try_parse_json content >>= fun json ->
  parse_req_body json >>= fun b ->
  nonempty b.unlockPassphrase >>= fun () ->
  nonempty b.adminPassphrase >>= fun () ->
  Ptime.of_rfc3339 b.time >>| fun time ->
  (b.unlockPassphrase, b.adminPassphrase, time)


module Make (Wm : Webmachine.S with type +'a io = 'a Lwt.t) = struct

  class handler hsm_state = object(self)
    inherit [Cohttp_lwt.Body.t] Wm.resource

    method private provision rd =
      let open Hsm in
      begin
        let body = rd.Webmachine.Rd.req_body in
        Cohttp_lwt.Body.to_string body >|= fun content ->
        match decode_json content with
        | Ok (unlock, admin, time) -> Hsm.provision hsm_state ~unlock ~admin time; Ok true
        | Error _ -> Error `Bad_request
      end >>= function
      | Ok body -> Wm.continue body rd
      | Error status -> Wm.respond (Cohttp.Code.code_of_status status) rd

    method private noop rd =
      Wm.continue `Empty rd

    (* we use this not for the service, but to check the internal state before processing requests *)
    method! service_available rd =
      if Access.is_in_state hsm_state `Unprovisioned
      then Wm.continue true rd
      else Wm.respond (Cohttp.Code.code_of_status `Precondition_failed) rd

    method !allowed_methods rd =
      Wm.continue [ `PUT ] rd
 
    method content_types_provided rd =
      Wm.continue [ ("text/html", self#noop) ] rd

    method content_types_accepted rd =
      Wm.continue [ ("application/json", self#provision) ] rd

  end

end
