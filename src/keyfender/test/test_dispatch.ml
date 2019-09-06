open OUnit

module Handlers = Keyfender.Server.Make_handlers(Mirage_random_test)(Pclock)

let now () = Ptime.v (Pclock.now_d_ps ())

let with_path path =
  let open Cohttp in
  let uri = Uri.make ~scheme:"http" ~host:"localhost" ~path () in
  let headers = Header.init_with "accept" "application/text" in
  let request = Request.make ~meth:`GET ~headers uri in
  Handlers.Wm.dispatch' (Handlers.routes Keyfender.Hsm.make now) ~body:`Empty ~request

let empty () =
  "an empty table will produce no result"
    @? begin match Lwt_main.run (with_path "/") with
       | None -> true
       | _    -> false
    end

(* translate from ounit into boolean *)
let rec ounit_success =
  function
    | [] -> true
    | RSuccess _::t
    | RSkip _::t ->
        ounit_success t
    | RFailure _::_
    | RError _::_
    | RTodo _::_ ->
        false

let () = 
  let tests = [
    "empty" >:: empty;
  ] in
  let suite = "test dispatch" >::: tests in
  let verbose = ref false in
  let set_verbose _ = verbose := true in
  Arg.parse
    [("-verbose", Arg.Unit set_verbose, "Run the test in verbose mode.");]
    (fun x -> raise (Arg.Bad ("Bad argument : " ^ x)))
    ("Usage: " ^ Sys.argv.(0) ^ " [-verbose]");
  if not (ounit_success (run_test_tt ~verbose:!verbose suite))
  then exit 1
