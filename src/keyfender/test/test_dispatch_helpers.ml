(* Copyright 2023 - 2023, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

(* stop execution on none *)
let (let*) v f =
  match v with
  | None -> ()
  | Some v -> f v

module Expect = struct

  type cohttp_response = 
    Cohttp.Code.status_code * 
    Cohttp.Header.t *
    Cohttp_lwt.Body.t *
    string list

  type 'a response = 'a * cohttp_response option

  let status_fmt f s =
    Fmt.string f (Cohttp.Code.string_of_status s)

  let status =
    Alcotest.testable (Fmt.option status_fmt) (Option.equal ( = ))

  let status_of_response r = Option.map (fun (a, _, _, _) -> a) r

  let body_type_fmt f = function
    | `String -> Fmt.string f "`String"
    | `Stream -> Fmt.string f "`Stream"
    | `Strings -> Fmt.string f "`Strings"
    | `Empty -> Fmt.string f "`Empty"

  let body_type =
    Alcotest.testable (Fmt.option body_type_fmt) (Option.equal ( = ))

  let body_type_of_response r = Option.map (function
      | (_, _, `Stream _, _) -> `Stream
      | (_, _, `String _, _) -> `String
      | (_, _, `Strings _, _) -> `Strings
      | (_, _, `Empty, _) -> `Empty) r

  let code c (hsm, response) =
    Alcotest.(check status) 
    "Response code"  
    (Some c)
    (status_of_response response);
    match response with
    | Some (s, _, _, _) when s = c -> Some hsm
    | _ -> None
  
  let no_content v = code `No_content v 

  let not_found v = code `Not_found v

  let ok v = code `OK v
    
  let stream (hsm, response) =
    Alcotest.(check status) 
      "Response code"
      (Some `OK)
      (status_of_response response);
    Alcotest.(check body_type) 
      "Response body type"
      (Some `Stream)
      (body_type_of_response response);
    match response with
    | Some (`OK, _, `Stream s, _) -> Some (hsm, s)
    | _ -> None

  let string expected (hsm, response) =
    Alcotest.(check status) 
      "Response code"
      (Some `OK)
      (status_of_response response);
    Alcotest.(check body_type) 
      "Response body type"
      (Some `String)
      (body_type_of_response response);
    match response with
    | Some (`OK, _, `String s, _) -> 
      Alcotest.(check string) "Response string" expected s;
      Some hsm
    | _ -> None
  
end
