module Make (Wm : Webmachine.S with type +'a io = 'a Lwt.t) (Hsm : Hsm.S) = struct

  module Endpoint = Endpoint.Make(Wm)(Hsm)

  class info hsm_state = object
    inherit Endpoint.base
    inherit Endpoint.get_json

    method private to_json =
      let json = Hsm.info hsm_state |> Json.info_to_yojson |> Yojson.Safe.to_string in
      Wm.continue (`String json)
  end

end
