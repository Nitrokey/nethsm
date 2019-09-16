open Lwt.Infix

module Make (Wm : Webmachine.S with type +'a io = 'a Lwt.t) (Hsm : Hsm.S) = struct

  module Access = Access.Make(Hsm)

  class handler hsm_state = object(self)
    inherit [Cohttp_lwt.Body.t] Wm.resource

    method private system_info rd =
      match Webmachine.Rd.lookup_path_info "ep" rd with
      | Some "info" -> 
        let open Hsm in
        let json = Yojson.Safe.to_string (system_info_to_yojson @@ system_info hsm_state) in
        Wm.continue (`String json) rd
      | _ -> Wm.respond (Cohttp.Code.code_of_status `Not_found) rd
       
    (* TODO we get 500 instead of 200 when we post to reset etc *)
    method private system rd =
      match Webmachine.Rd.lookup_path_info "ep" rd with
      | Some "reboot" -> 
        Hsm.reboot () ;
        Wm.continue true rd
      | Some "shutdown" -> 
        Hsm.shutdown () ;
        Wm.continue true rd
      | Some "reset" ->
        Hsm.reset () ;
        Wm.continue true rd
      | Some "update" ->  Wm.respond (Cohttp.Code.code_of_status `Not_found) rd
      | Some "backup" ->  Wm.respond (Cohttp.Code.code_of_status `Not_found) rd
      | Some "restore" -> Wm.respond (Cohttp.Code.code_of_status `Not_found) rd
      | _ -> Wm.respond (Cohttp.Code.code_of_status `Not_found) rd

    (* we use this not for the service, but to check the internal state before processing requests *)
    method! service_available rd =
      if Access.is_in_state hsm_state `Operational
      then Wm.continue true rd
      else Wm.respond (Cohttp.Code.code_of_status `Precondition_failed) rd

    method! is_authorized rd =
      Access.is_authorized hsm_state rd >>= fun (auth, rd') ->
      Wm.continue auth rd'

    method! forbidden rd =
      Access.forbidden hsm_state Hsm.Administrator rd >>= fun auth ->
      Wm.continue auth rd

    method !process_post rd =
      Wm.continue true rd 

    method !allowed_methods rd =
      Wm.continue [ `GET ; `POST ] rd
 
    method content_types_provided rd =
      Wm.continue [ ("application/json", self#system_info) ] rd

    method content_types_accepted rd =
      Wm.continue [ ("application/json", self#system) ] rd

  end

end
