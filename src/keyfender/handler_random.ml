open Lwt.Infix

module Make (Wm : Webmachine.S with type +'a io = 'a Lwt.t) (Hsm : Hsm.S) = struct

  module Access = Access.Make(Hsm)

  class handler hsm_state = object(self)
    inherit [Cohttp_lwt.Body.t] Wm.resource

    method private random rd =
      let body = rd.Webmachine.Rd.req_body in
      Cohttp_lwt.Body.to_string body >>= fun length ->
      match int_of_string length with
      | exception Failure _ -> Wm.respond (Cohttp.Code.code_of_status `Bad_request) rd
      | l -> 
        let data = Hsm.random l in
        let json = Yojson.Safe.to_string (`String data) in
        Wm.respond ~body:(`String json) (Cohttp.Code.code_of_status `OK) rd
       
    method private empty rd =
      Wm.continue `Empty rd

    (* we use this not for the service, but to check the internal state before processing requests *)
    method! service_available rd =
      if Access.is_in_state hsm_state `Operational
      then Wm.continue true rd
      else Wm.respond (Cohttp.Code.code_of_status `Precondition_failed) rd

    method! is_authorized rd =
      Access.is_authorized hsm_state rd >>= fun (auth, rd') ->
      Wm.continue auth rd'

    method! forbidden rd =
      (* TODO role should be operator but we don't have it yet *)
      Access.forbidden hsm_state `Administrator rd >>= fun auth ->
      Wm.continue auth rd

    method !process_post rd =
      self#random rd

    method !allowed_methods rd =
      Wm.continue [ `GET ; `POST ] rd
 
    method content_types_provided rd =
      Wm.continue [ ("application/json", self#empty) ] rd

    method content_types_accepted rd =
      Wm.continue [ ("application/json", self#random) ] rd
  end

end
