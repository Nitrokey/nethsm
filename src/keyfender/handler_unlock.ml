open Lwt.Infix

type req_body = { passphrase : string }[@@deriving yojson]

let decode_json json =
  let open Rresult.R.Infix in
  Json.to_ocaml req_body_of_yojson json >>= fun b ->
  Json.nonempty ~name:"passphrase" b.passphrase >>| fun () ->
  b.passphrase

module Make (Wm : Webmachine.S with type +'a io = 'a Lwt.t) (Hsm : Hsm.S) = struct

  module Endpoint = Endpoint.Make(Wm)(Hsm)
  module Utils = Wm_utils.Make(Wm)(Hsm)

  class unlock hsm_state = object
    inherit Endpoint.put_json hsm_state

    method private of_json json rd =
      let ok passphrase =
        Hsm.unlock_with_passphrase hsm_state ~passphrase >>= function
        | Ok () -> Wm.continue true rd
        | Error e -> Utils.respond_error e rd
      in
      decode_json json |> Utils.err_to_bad_request ok rd

    method private required_states = Wm.continue [ `Locked ]
  end
end
