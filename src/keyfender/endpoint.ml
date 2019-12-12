open Lwt.Infix

module Make (Wm : Webmachine.S with type +'a io = 'a Lwt.t) (Hsm : Hsm.S) = struct

  module Access = Access.Make(Hsm)

  class virtual hsm hsm_state = object(self)
    inherit [Cohttp_lwt.Body.t] Wm.resource

    method virtual private required_states :
      (Hsm.state list, Cohttp_lwt.Body.t) Wm.op

    method! service_available rd =
      self#required_states rd >>= function
      | Ok states, rd' ->
        if List.exists (Access.is_in_state hsm_state) states
        then Wm.continue true rd'
        else Wm.respond (Cohttp.Code.code_of_status `Precondition_failed) rd'
      | Error code, rd' ->
        Wm.respond code rd'
  end

  class virtual get_json hsm_state = object(self)
    inherit hsm hsm_state

    method virtual private to_json : Cohttp_lwt.Body.t Wm.provider

    method content_types_provided =
      Wm.continue [ ("application/json", self#to_json) ]

    method content_types_accepted =
      Wm.continue [ ]
  end

  module Utils = Wm_utils.Make(Wm)(Hsm)

  class virtual put_json hsm_state = object(self)
    inherit hsm hsm_state

    method virtual private of_json : Yojson.Safe.t ->
      Cohttp_lwt.Body.t Wm.acceptor

    method content_types_provided =
      Wm.continue [ ("application/json", Wm.continue `Empty) ]

    method private parse_json rd =
      let body = rd.Webmachine.Rd.req_body in
      Cohttp_lwt.Body.to_string body >>= fun content ->
      try self#of_json (Yojson.Safe.from_string content) rd
      with Yojson.Json_error msg ->
        Utils.respond_error
          (Hsm.Bad_request, Printf.sprintf "Invalid JSON: %s." msg)
          rd

    method content_types_accepted =
      Wm.continue [  ("application/json", self#parse_json) ]

    method !allowed_methods = Wm.continue [ `PUT ]
  end

  class virtual post hsm_state = object(self)
    inherit hsm hsm_state

    method content_types_accepted =
      Wm.continue [ ("application/json", self#process_post) ]

    method content_types_provided =
      Wm.continue [ ("application/json", Wm.continue `Empty) ]

    method !allowed_methods = Wm.continue [ `POST ]
  end

  class virtual post_json hsm_state = object(self)
    inherit post hsm_state

    method virtual private of_json : Yojson.Safe.t ->
      Cohttp_lwt.Body.t Wm.acceptor

    method private parse_json rd =
      let body = rd.Webmachine.Rd.req_body in
      Cohttp_lwt.Body.to_string body >>= fun content ->
      try self#of_json (Yojson.Safe.from_string content) rd
      with Yojson.Json_error msg ->
        Utils.respond_error
          (Hsm.Bad_request, Printf.sprintf "Invalid JSON: %s." msg)
          rd

    method !process_post = self#parse_json
  end

end
