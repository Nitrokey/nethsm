open Lwt.Infix

module Make (Wm : Webmachine.S with type +'a io = 'a Lwt.t) (Hsm : Hsm.S) = struct

  module Endpoint = Endpoint.Make(Wm)(Hsm)

  class unlock hsm_state = object
    inherit Endpoint.base
    inherit !Endpoint.input_state_validated hsm_state [ `Locked ]
    inherit !Endpoint.put_json 

    method private of_json json rd =
      let ok passphrase =
        Hsm.unlock_with_passphrase hsm_state ~passphrase >>= function
        | Ok () -> Wm.continue true rd
        | Error e -> Endpoint.respond_error e rd
      in
      Json.decode_passphrase json |> Endpoint.err_to_bad_request ok rd
  end
end
