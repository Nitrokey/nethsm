open Lwt.Infix

module Make (Wm : Webmachine.S with type +'a io = 'a Lwt.t) = struct
  type req_body = { unlockPassphrase : string ; adminPassphrase : string ; time : string }[@@deriving yojson]

  class handler hsm_state = object(self)
    inherit [Cohttp_lwt.Body.t] Wm.resource

    method private provision rd =
      let open Hsm in
      begin
        let body = rd.Webmachine.Rd.req_body in
        Cohttp_lwt.Body.to_string body >|= fun content ->
        try 
          let json = Yojson.Safe.from_string content in
          match req_body_of_yojson json with
          | Error e -> Error `Bad_request
          | Ok req_body ->
            let unlock = req_body.unlockPassphrase in
            let admin = req_body.adminPassphrase in
            if String.length unlock == 0 || String.length admin == 0 
            then Error `Bad_request
            else 
              match Ptime.of_rfc3339 req_body.time with
              | Ok time ->
                Hsm.provision hsm_state ~unlock ~admin time;
                Ok true
              | Error e -> Error `Bad_request
        with Yojson.Safe.Finally _ -> Error `Bad_request
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
