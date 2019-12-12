module Make (Wm : Webmachine.S with type +'a io = 'a Lwt.t) (Hsm : Hsm.S) = struct
  module Endpoint = Endpoint.Make(Wm)(Hsm)

  class random hsm_state = object
    inherit Endpoint.base
    inherit !Endpoint.input_state_validated hsm_state [ `Operational ]
    inherit !Endpoint.role hsm_state `Operator
    inherit !Endpoint.post_json

    method private of_json json rd =
      let ok ({ Json.length } : Json.random_req ) =
        let data = Hsm.random length in
        let json = Yojson.Safe.to_string (`Assoc [ "random" , `String data ]) in
        Wm.respond ~body:(`String json) (Cohttp.Code.code_of_status `OK) rd
      in
      Json.to_ocaml Json.random_req_of_yojson json |> Endpoint.err_to_bad_request ok rd
  end
end
