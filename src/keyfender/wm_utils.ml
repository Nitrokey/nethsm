module Make (Wm : Webmachine.S with type +'a io = 'a Lwt.t) (Hsm : Hsm.S) = struct

  let respond_error (e, body) rd = 
    let code = Hsm.error_to_code e in
    Wm.respond ~body:(`String body) code rd  

end
