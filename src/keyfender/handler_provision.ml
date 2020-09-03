open Lwt.Infix

module Make (Wm : Webmachine.S with type +'a io = 'a Lwt.t) (Hsm : Hsm.S) = struct

  module Endpoint = Endpoint.Make(Wm)(Hsm)

  class provision hsm_state = object
    inherit Endpoint.base_with_body_length
    inherit !Endpoint.input_state_validated hsm_state [ `Unprovisioned ]
    inherit !Endpoint.post_json
    inherit !Endpoint.no_cache

    method private of_json json rd =
      let ok (unlock, admin, time) =
          Hsm.provision hsm_state ~unlock ~admin time >>= function
          | Ok () -> Wm.continue true rd
          | Error e -> Endpoint.respond_error e rd
      in
      Json.decode_provision_req json |> Endpoint.err_to_bad_request ok rd
  end
end
