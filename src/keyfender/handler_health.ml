module Make (Wm : Webmachine.S) (Hsm : Hsm.S) = struct
  class handler hsm_state = object(self)
    inherit [Cohttp_lwt.Body.t] Wm.resource

    method private to_json rd =
      let ep = Webmachine.Rd.lookup_path_info_exn "ep" rd in
      let result = match ep, Hsm.state hsm_state with
        | "alive", (`Locked | `Unprovisioned) -> Ok `Empty
        | "ready", `Operational -> Ok `Empty
        | "state", state ->
          let json = Yojson.Safe.to_string (Hsm.state_to_yojson state) in
          Ok (`String json)
        | _, _ -> Error `Precondition_failed (*TODO assert false if wrong endpoint?*) 
      in
      match result with
      | Ok body -> Wm.continue body rd
      | Error status -> Wm.respond (Cohttp.Code.code_of_status status) rd

    method! resource_exists rd =
      match Webmachine.Rd.lookup_path_info_exn "ep" rd with
     | "alive"
     | "ready"
     | "state" -> Wm.continue true rd
     | _ -> Wm.continue false rd

    method content_types_provided rd =
      Wm.continue [ ("application/json", self#to_json) ] rd

    method content_types_accepted rd =
      Wm.continue [ ] rd

  end

end
