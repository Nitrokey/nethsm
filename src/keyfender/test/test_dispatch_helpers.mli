(* Copyright 2023 - 2023, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

val ( let* ) : 'a option -> ('a -> unit) -> unit

module Expect :
sig
  type cohttp_response = 
    Cohttp.Code.status_code * 
    Cohttp.Header.t *
    Cohttp_lwt.Body.t *
    string list

  type 'hsm response = 'hsm * cohttp_response option

  val ok : 'hsm response -> 'hsm option

  val not_found : 'hsm response -> 'hsm option

  val no_content : 'hsm response -> 'hsm option

  val stream : 'hsm response -> ('hsm * string Lwt_stream.t) option

  val string : string -> 'hsm response -> 'hsm option
end
