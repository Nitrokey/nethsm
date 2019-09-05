module Make (Wm : Webmachine.S) = struct
  class handler = object(self)
    inherit [Cohttp_lwt.Body.t] Wm.resource

    method private to_json rd =
      let result = match Webmachine.Rd.lookup_path_info "ep" rd with
      | None -> Error `Bad_request
      | Some ep -> match ep, Backend.state with
        | "alive", (`Locked | `Unprovisioned) -> Ok `Empty
        | "ready", `Operational -> Ok `Empty
        | "state", state -> 
            let json = Yojson.Safe.to_string (Backend.state_to_yojson state) in
            Ok (`String json)
        | _, _ -> Error `Payment_required
      in
      match result with
      | Ok body -> Wm.continue body rd
      | Error status -> Wm.respond (Cohttp.Code.code_of_status status) rd

    method content_types_provided rd =
      Wm.continue [ ("application/json", self#to_json) ] rd

    method content_types_accepted rd =
      Wm.continue [ ] rd

  end

end
