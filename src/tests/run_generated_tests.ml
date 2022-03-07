
(* execute [fn] with current working directory changed to [directory] *)
let in_dir directory fn =
  let old = Unix.getcwd () in
  Unix.chdir directory;
  Fun.protect 
    ~finally:(fun () -> Unix.chdir old)
    fn

(* list the content of [dir], excluding dot files *)
let ls dir =
  let dir = Unix.opendir dir in
  let rec ls dirs = match Unix.readdir dir with
    | dirname when dirname.[0] = '.' -> ls dirs
    | dirname -> ls (dirname::dirs)
    | exception End_of_file -> Unix.closedir dir; dirs
  in
  ls []
  |> List.sort String.compare

let (let*) = Result.bind 

let command_suffix = "_cmd.sh"

let command_suffix_len = String.length command_suffix

(* 
parse the output header file to obtain the response code. 

example: if the content is 
"""
HTTP/1.1 400 Bad Request
content-length: 83
content-type: application/json
date: Tue, 22 Feb 2022 14:22:21 GMT
vary: Accept, Accept-Encoding, Accept-Charset, Accept-Language
"""

the output is "400"
*)
let actual_code file =
  let* content = Bos.OS.File.read_lines file in
  List.find_map (fun line ->
    if Astring.String.is_prefix ~affix:"HTTP" line then 
      match String.split_on_char ' ' line with
      | _::code::_ -> Some code
      | _ -> None 
    else None
  ) content
  |> Option.to_result ~none:(`Msg ("actual_code of " ^ Fpath.to_string file))

(* 
extract the expected code from the file name:

expected_code "400_wrong_json_headers.out" => "400" *)
let expected_code v = 
  match String.split_on_char '_' v with
  | code::_ -> Ok code
  | _ -> Error (`Msg "expected_code: unknown")

(* perform the API output test *)
let test_error test =
  let open Bos in
  let* () = 
    OS.Cmd.run Cmd.(v ("./"^test^command_suffix))
  in
  let headers_file = Fpath.v (test^"_headers.out") in
  let* actual_code = actual_code headers_file in
  let* expected_code = expected_code test in
  Alcotest.(check string) (test^": code matches") expected_code actual_code;
  Ok ()

(* print the content of the file descriptor*)
let tail fd =
  let rec loop () =
    match input_line fd with
    | line -> 
      Printf.eprintf "%s\n%!" line;
      loop ()
    | exception End_of_file -> ()
  in
  loop ()

(* wait until the server is ready, by listening on the server's standard error
and waiting for the "listening on 8080" message. Then, a thread is spawned to 
continue printing the server's logs while the function returns.  *)
let wait_until_ready (_, _, proc_stderr) =
  let rec wait () =
    let line = input_line proc_stderr in
    Printf.eprintf "%s\n%!" line;
    if Astring.String.is_infix ~affix:"listening on 8080" line then
      Thread.create tail proc_stderr
    else
      wait () 
  in
  wait ()

(* expected to be run from a "generated/XXX" folder, this function 
tests a specific endpoint. *)
let tests_endpoint () =
  (* 1: start the server*)
  let server_process = Unix.open_process_args_full 
    "../../../keyfender/_build/default/test/test_server.exe" 
    [||]
    (Unix.environment ())
  in
  let server_pid = Unix.process_full_pid server_process in
  (* 2: wait until the server is ready *)
  let th = wait_until_ready server_process in
  try
    (* 3: perform endpoint-specific setup *)
    let () =
      Bos.(OS.Cmd.run Cmd.(v "./setup.sh")) 
      |> function
      | Ok () -> ()
      | Error (`Msg e) -> Alcotest.fail ("setup: "^e)
    in
    Printf.printf "PWD: %s" (Unix.getcwd ());
    (* 4: perform error tests *)
    let () =
      ls "."
      |> List.filter_map (fun s ->
        if Astring.String.is_suffix ~affix:command_suffix s then
          Some (String.(sub s 0 (length s - command_suffix_len)))
        else None)
      |> List.map test_error
      |> List.iter (function
      | Ok () -> ()
      | Error (`Msg msg) -> Alcotest.fail msg)
    in
    (* 5: perform happy-path test *)
    let () =
      if Bos.OS.Path.exists (Fpath.v "cmd.sh") |> Result.get_ok then
        begin
          let* () = 
            Bos.(OS.Cmd.run Cmd.(v ("./cmd.sh")))
          in
          let* expected_code = actual_code Fpath.(v "headers.expected") in
          let* actual_code = actual_code Fpath.(v "headers.out") in
          Alcotest.(check string) ("CMD: code matches") expected_code actual_code;
          Ok ()
        end
        |> function
        | Ok () -> ()
        | Error (`Msg msg) -> Alcotest.fail msg
    in
    (* 6: server tear down *)
    match Bos.(OS.Cmd.run Cmd.(v ("./shutdown.sh"))) with
    | Ok () -> ()
    | Error _ -> Unix.kill server_pid 15;
    Unix.close_process_full server_process |> ignore;
    Thread.join th
  with
  | e ->
    (* exception: server tear down *)
    Unix.kill server_pid 15;
    Unix.close_process_full server_process |> ignore;
    Thread.join th;
    raise e
let tests =
  ls "generated"
  |> 
  List.map (fun endpoint -> 
    endpoint, 
    [
      Alcotest.test_case "OK" `Quick @@ fun () -> 
      in_dir ("generated/"^endpoint) tests_endpoint
    ])

let () =
  Alcotest.run ~argv:Sys.argv "api" tests 