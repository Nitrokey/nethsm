module Make (Wm : Webmachine.S) = struct
  class handler hsm_state = object(self)
    inherit [Cohttp_lwt.Body.t] Wm.resource

    method private to_json rd =
      let open Hsm in
      let json = Yojson.Safe.to_string (info_to_yojson @@ info hsm_state) in
      Wm.continue (`String json) rd

    method content_types_provided rd =
      Wm.continue [ ("application/json", self#to_json) ] rd

    method content_types_accepted rd =
      Wm.continue [ ] rd

  end

end
