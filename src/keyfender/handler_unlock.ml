open Lwt.Infix

type req_body = { passphrase : string }[@@deriving yojson]

let nonempty s =
  if String.length s == 0
  then Error `Bad_request
  else Ok ()
 
let try_parse_json content = 
  try 
    Ok (Yojson.Safe.from_string content)
  with _ -> Error `Bad_request

let parse_req_body json =
  Rresult.R.reword_error (fun _ -> `Bad_request) @@ req_body_of_yojson json
 
let decode_json content =
  let open Rresult.R.Infix in
  try_parse_json content >>= fun json ->
  parse_req_body json >>= fun b ->
  nonempty b.passphrase >>= fun () ->
  Ok b.passphrase

module Make (Wm : Webmachine.S with type +'a io = 'a Lwt.t) (Hsm : Hsm.S) = struct

  module Access = Access.Make(Hsm)

  class handler hsm_state = object(self)
    inherit [Cohttp_lwt.Body.t] Wm.resource

    method private unlock rd =
      begin
        let body = rd.Webmachine.Rd.req_body in
        Cohttp_lwt.Body.to_string body >>= fun content ->
        match decode_json content with
        | Ok passphrase -> Hsm.unlock_with_passphrase hsm_state ~passphrase
        | Error _ -> Lwt.return (Error `Bad_request)
      end >>= function
      | Ok () -> Wm.continue true rd
      | Error _ -> Wm.respond (Cohttp.Code.code_of_status `Bad_request) rd

    method private noop rd =
      Wm.continue `Empty rd

    (* we use this not for the service, but to check the internal state before processing requests *)
    method! service_available rd =
      if Access.is_in_state hsm_state `Locked
      then Wm.continue true rd
      else Wm.respond (Cohttp.Code.code_of_status `Precondition_failed) rd

    method !allowed_methods rd =
      Wm.continue [ `PUT ] rd
 
    method content_types_provided rd =
      Wm.continue [ ("text/html", self#noop) ] rd

    method content_types_accepted rd =
      Wm.continue [ ("application/json", self#unlock) ] rd

  end

end
