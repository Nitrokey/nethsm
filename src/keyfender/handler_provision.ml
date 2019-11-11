open Lwt.Infix

type req_body = { unlockPassphrase : string ; adminPassphrase : string ; time : string }[@@deriving yojson]

let decode_json content =
  let open Rresult.R.Infix in
  Json.decode req_body_of_yojson content >>= fun b ->
  Json.nonempty ~name:"unlockPassphrase" b.unlockPassphrase >>= fun () ->
  Json.nonempty ~name:"adminPassphrase" b.adminPassphrase >>= fun () ->
  Json.decode_time b.time >>| fun time ->
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
