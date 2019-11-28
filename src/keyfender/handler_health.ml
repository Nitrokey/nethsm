module Make (Wm : Webmachine.S with type +'a io = 'a Lwt.t) (Hsm : Hsm.S) = struct

  module Endpoint = Endpoint.Make(Wm)(Hsm)

  class alive hsm_state = object
    inherit Endpoint.get_json hsm_state

    method private to_json = Wm.continue `Empty

    method private required_states = Wm.continue [ `Locked ; `Unprovisioned ]
  end

  class ready hsm_state = object
    inherit Endpoint.get_json hsm_state

    method private to_json = Wm.continue `Empty

    method private required_states = Wm.continue [ `Operational ]
  end

  class state hsm_state = object
    inherit Endpoint.get_json hsm_state

    method private to_json =
      let state = Hsm.state hsm_state in
      let json = Yojson.Safe.to_string (Hsm.state_to_yojson state) in
      Wm.continue (`String json)

    method private required_states =
      Wm.continue [ `Unprovisioned ; `Operational ; `Locked ; `Busy ]
  end
end
