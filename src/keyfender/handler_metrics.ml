module Make (Wm : Webmachine.S with type +'a io = 'a Lwt.t) (Hsm : Hsm.S) = struct

  module Endpoint = Endpoint.Make(Wm)(Hsm)

  class handler _hsm_state = object(self)
    inherit Endpoint.base

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
