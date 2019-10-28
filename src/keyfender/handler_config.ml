open Lwt.Infix

module Make (Wm : Webmachine.S with type +'a io = 'a Lwt.t) (Hsm : Hsm.S) = struct

  module Access = Access.Make(Hsm)

  class handler hsm_state = object(self)
    inherit [Cohttp_lwt.Body.t] Wm.resource

    method private get rd =
      match Webmachine.Rd.lookup_path_info "ep" rd with
      | Some "unattended-boot" -> 
        let json = "TODO: GET unattended-boot" in
        Wm.continue (`String json) rd
      | Some "tls/public-pem" -> 
        let json = "TODO: GET public.pem" in
        Wm.continue (`String json) rd
      | Some "tls/cert-pem" -> 
        let json = "TODO: GET cert.pem" in
        Wm.continue (`String json) rd
      | Some "network" -> 
        Hsm.Config.network hsm_state >>= fun _network ->
        (* TODO serialise network to json and a string *)
        let json = "TODO: GET network" in
        Wm.continue (`String json) rd
      | Some "logging" -> 
        let json = "TODO: GET logging" in
        Wm.continue (`String json) rd
      | Some "time" -> 
        let json = "todo: GET time" in
        Wm.continue (`String json) rd
      | _ -> Wm.respond (Cohttp.Code.code_of_status `Not_found) rd
 
    (* TODO we get 500 instead of 200 when we post to reset etc *)
    method private config rd =
      match Webmachine.Rd.lookup_path_info "ep" rd with
      | Some "unlock-passphrase" -> 
        let passphrase = "TODO" in
        Hsm.Config.change_unlock_passphrase hsm_state ~passphrase >>= fun _res ->
        Wm.continue true rd
      | Some "unattended-boot" -> 
        Hsm.Config.unattended_boot () ;
        Wm.continue true rd
      (* TODO elegant way to match on deep path *)
      | Some "tls" -> assert false
      (* tls/public.pem supports get only *)
      | Some "network" ->
        (* TODO decode network configuration from user data *)
        let network =
          Ipaddr.V4.{ Hsm.Config.ipAddress = localhost ;
                      netmask = Prefix.(netmask loopback) ;
                      gateway = localhost }
        in
        Hsm.Config.change_network hsm_state network >>= fun _ ->
        Wm.continue true rd
      | Some "logging" ->
        Hsm.Config.logging () ;
        Wm.continue true rd
      | Some "backup-passphrase" ->
        Hsm.Config.backup_passphrase () ;
        Wm.continue true rd
      | Some "time" ->
        Hsm.Config.time () ;
        Wm.continue true rd
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
      Access.forbidden hsm_state `Administrator rd >>= fun auth ->
      Wm.continue auth rd

    method !process_post rd =
      Wm.continue true rd 

    method !allowed_methods rd =
      Wm.continue [ `GET ; `POST ; `PUT ] rd
 
    method content_types_provided rd =
      Wm.continue [ ("application/json", self#get) ] rd

    method content_types_accepted rd =
      Wm.continue [ ("application/json", self#config) ] rd

  end

end
