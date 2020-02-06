module Make (Wm : Webmachine.S with type +'a io = 'a Lwt.t) (Hsm : Hsm.S) = struct

  module Endpoint = Endpoint.Make(Wm)(Hsm)

  class metrics hsm_state ip = object(self)
    inherit Endpoint.base_with_body_length
    inherit !Endpoint.input_state_validated hsm_state [ `Operational ]
    inherit !Endpoint.role hsm_state `Metrics ip
    inherit !Endpoint.no_cache

    method private to_json rd =
      let data = Hsm.Metrics.retrieve () in
      let json = `Assoc (List.map (fun (k, v) -> k, `String v) data) in
      let body = Yojson.Safe.to_string json in
      Wm.continue (`String body) rd

    method content_types_provided rd =
      Wm.continue [ ("application/json", self#to_json) ] rd

    method content_types_accepted rd =
      Wm.continue [ ] rd
  end
end
