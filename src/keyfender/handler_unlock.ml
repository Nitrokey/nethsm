open Lwt.Infix

module Make (Wm : Webmachine.S with type +'a io = 'a Lwt.t) (Hsm : Hsm.S) = struct

  module Endpoint = Endpoint.Make(Wm)(Hsm)

  let unlock_user = "_unlock" (* valid_user is alphanumeric *)

  class unlock hsm_state ip = object
    inherit Endpoint.base_with_body_length
    inherit !Endpoint.input_state_validated hsm_state [ `Locked ]
    inherit !Endpoint.post_json
    inherit !Endpoint.no_cache

    method private of_json json rd =
      if Rate_limit.within (Hsm.now ()) ip unlock_user
      then
        let ok passphrase =
          Hsm.unlock_with_passphrase hsm_state ~passphrase >>= function
          | Ok () ->
            Rate_limit.reset ip unlock_user;
            Wm.continue true rd
          | Error e -> Endpoint.respond_error e rd
        in
        Json.decode_passphrase json |> Endpoint.err_to_bad_request ok rd
      else
        Endpoint.respond_error
          (Too_many_requests, "Service unavailable: too many requests")
          rd
  end

  class lock hsm_state ip = object
    inherit Endpoint.base_with_body_length
    inherit !Endpoint.input_state_validated hsm_state [ `Operational ]
    inherit !Endpoint.role hsm_state `Administrator ip
    inherit !Endpoint.post
    inherit !Endpoint.no_cache

    method! process_post rd =
      Hsm.lock hsm_state ;
      Wm.continue true rd
  end
end
