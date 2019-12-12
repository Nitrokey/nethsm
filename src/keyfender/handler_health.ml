module Make (Wm : Webmachine.S with type +'a io = 'a Lwt.t) (Hsm : Hsm.S) = struct

  module Endpoint = Endpoint.Make(Wm)(Hsm)

  class alive hsm_state = object
    inherit Endpoint.base
    inherit !Endpoint.input_state_validated hsm_state [ `Locked ; `Unprovisioned ]
    inherit Endpoint.get_json

    method private to_json = Wm.continue `Empty
  end

  class ready hsm_state = object
    inherit Endpoint.base
    inherit !Endpoint.input_state_validated hsm_state [ `Operational ]
    inherit Endpoint.get_json

    method private to_json = Wm.continue `Empty
  end

  class state hsm_state = object
    inherit Endpoint.base
    inherit Endpoint.get_json

    method private to_json =
      let state = Hsm.state hsm_state in
      let json = Yojson.Safe.to_string (Hsm.state_to_yojson state) in
      Wm.continue (`String json)
  end
end
