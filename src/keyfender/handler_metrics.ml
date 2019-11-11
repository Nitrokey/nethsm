module Make (Wm : Webmachine.S) (Hsm : Hsm.S) = struct
  class handler _hsm_state = object(self)
    inherit [Cohttp_lwt.Body.t] Wm.resource

    method private to_json rd =
      let result = 
            let metrics = "" in
            Ok (`String metrics)
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
