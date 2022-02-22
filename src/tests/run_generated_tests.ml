

let in_dir directory fn =
  let old = Unix.getcwd () in
  Unix.chdir directory;
  let res = fn () in
  Unix.chdir old;
  res

let test () = ()

let ls dir =
  let dir = Unix.opendir dir in
  let rec ls dirs = match Unix.readdir dir with
    | dirname when dirname.[0] = '.' -> ls dirs
    | dirname -> ls (dirname::dirs)
    | exception End_of_file -> Unix.closedir dir; dirs
  in
  ls []
  |> List.sort String.compare

let status_to_result msg = 
  function
  | Unix.WEXITED 0 -> Ok ()
  | _ -> Error msg

let (let*) = Result.bind 

let suffix = "_cmd.sh"

let suffix_len = String.length suffix

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

let expected_code v = 
  match String.split_on_char '_' v with
  | code::_ -> Ok code
  | _ -> Error (`Msg "expected_code: unknown")

let test_error test =
  let open Bos in
  let* () = 
    OS.Cmd.run Cmd.(v ("./"^test^suffix))
  in
  let headers_file = Fpath.v (test^"_headers.out") in
  let* actual_code = actual_code headers_file in
  let* expected_code = expected_code test in
  Alcotest.(check string) (test^": code matches") expected_code actual_code;
  Ok ()

let tail_err fd =
  let rec loop () =
    match input_line fd with
    | line -> 
      Printf.eprintf "%s\n%!" line;
      loop ()
    | exception End_of_file -> ()
  in
  loop ()

let wait_until_ready (_, _, proc_stderr) =
  let rec wait () =
    let line = input_line proc_stderr in
    Printf.eprintf "%s\n%!" line;
    if Astring.String.is_infix ~affix:"listening on 8080" line then
      Thread.create tail_err proc_stderr
    else
      wait () 
  in
  wait ()

let tests_endpoint () =
  let server_process = Unix.open_process_args_full 
    "../../../keyfender/_build/default/test/test_server.exe" 
    [||]
    (Unix.environment ())
  in
  let server_pid = Unix.process_full_pid server_process in
  let th = wait_until_ready server_process in
  try
    let () =
      Bos.(OS.Cmd.run Cmd.(v "./setup.sh")) 
      |> function
      | Ok () -> ()
      | Error (`Msg e) -> Alcotest.fail ("setup: "^e)
    in
    Printf.printf "PWD: %s" (Unix.getcwd ());
    let () =
      ls "."
      |> List.filter_map (fun s ->
        if Astring.String.is_suffix ~affix:suffix s then
          Some (String.(sub s 0 (length s - suffix_len)))
        else None)
      |> List.map test_error
      |> List.iter (function
      | Ok () -> ()
      | Error (`Msg msg) -> Alcotest.fail msg)
    in
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
    match Bos.(OS.Cmd.run Cmd.(v ("./shutdown.sh"))) with
    | Ok () -> ()
    | Error _ -> Unix.kill server_pid 15;
    Unix.close_process_full server_process |> ignore;
    Thread.join th
  with
  | e ->
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