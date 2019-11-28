module Make (Wm : Webmachine.S with type +'a io = 'a Lwt.t) (Hsm : Hsm.S) = struct

  module Endpoint = Endpoint.Make(Wm)(Hsm)

  class info hsm_state = object
    inherit Endpoint.get_json hsm_state

    method private to_json =
      let json =
        Hsm.(info hsm_state |> info_to_yojson |> Yojson.Safe.to_string)
      in
      Wm.continue (`String json)

    method private required_states =
      Wm.continue [ `Unprovisioned ; `Operational ; `Locked ; `Busy ]
  end

end
