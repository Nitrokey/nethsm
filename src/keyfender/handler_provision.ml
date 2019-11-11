open Lwt.Infix

type req_body = { unlockPassphrase : string ; adminPassphrase : string ; time : string }[@@deriving yojson]

let decode_json content =
  let open Rresult.R.Infix in
  Json.decode req_body_of_yojson content >>= fun b ->
  Json.nonempty_new ~name:"unlockPassphrase" b.unlockPassphrase >>= fun () ->
  Json.nonempty_new ~name:"adminPassphrase" b.adminPassphrase >>= fun () ->
  (* since ~sub:true is _not_ passed to of_rfc3339,
     no trailing bytes (third return value will be String.length b.time) *)
  Rresult.R.reword_error (function `RFC3339 ((start, stop), e) -> 
    Fmt.strf "Failed to decode timestamp: %a at position %d to %d." Ptime.pp_rfc3339_error e start stop) 
    (Ptime.of_rfc3339 b.time) >>= fun (time, off, _) ->
  (* according to spec, we accept only UTC timestamps! *)
  (match off with None | Some 0 -> Ok () | _ -> Error "Error while parsing timestamp. Offset must be 0.") >>| fun () ->
  (b.unlockPassphrase, b.adminPassphrase, time)


module Make (Wm : Webmachine.S with type +'a io = 'a Lwt.t) (Hsm : Hsm.S) = struct

  module Access = Access.Make(Hsm)
  module Utils = Wm_utils.Make(Wm)(Hsm)

  class handler hsm_state = object(self)
    inherit [Cohttp_lwt.Body.t] Wm.resource

    method private provision rd =
      let body = rd.Webmachine.Rd.req_body in
      Cohttp_lwt.Body.to_string body >>= fun content ->
      match decode_json content with
      | Error m -> Utils.respond_error (Bad_request, m) rd
      | Ok (unlock, admin, time) -> 
        Hsm.provision hsm_state ~unlock ~admin time >>= function
        | Ok () -> Wm.continue true rd
        | Error e -> Utils.respond_error e rd

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
