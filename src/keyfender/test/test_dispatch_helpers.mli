val ( let* ) : 'a option -> ('a -> unit) -> unit

module Expect :
sig
  type cohttp_response = 
    Cohttp.Code.status_code * 
    Cohttp.Header.t *
    Cohttp_lwt.Body.t *
    string list

  type 'a response = 'a * cohttp_response option

  val ok : 'a response -> 'a option

  val not_found : 'a response -> 'a option

  val no_content : 'a response -> 'a option

  val stream : 'a response -> ('a * string Lwt_stream.t) option

end
