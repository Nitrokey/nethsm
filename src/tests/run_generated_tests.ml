(* Copyright 2023 - 2023, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

module type BACKEND = sig
  type ctx
  type t

  val start : unit -> t
  val stop : t -> unit
  val init : unit -> ctx
  val finish : ctx -> unit
end

module UnixApp = struct
  type t = {
    (* the log output thread *)
    thread : Thread.t;
    (* process ID *)
    server_pid : int;
    server_process : in_channel * out_channel * in_channel;
  }

  (* print the content of the file descriptor*)
  let tail fd =
    let rec loop () =
      match input_line fd with
      | line ->
          Printf.eprintf "%s\n%!" line;
          loop ()
      | exception End_of_file -> ()
      | exception Sys_error s -> Printf.printf "Sys_error: %s\n%!" s
    in
    loop ()

  (* wait until the server is ready, by listening on the server's standard error
     and waiting for the "listening on 8080" message. Then, a thread is spawned to
     continue printing the server's logs while the function returns. *)
  let wait_until_ready ~message (_, _, proc_stderr) =
    let rec wait () =
      let line = input_line proc_stderr in
      Printf.eprintf "%s\n%!" line;
      if Astring.String.is_infix ~affix:message line then
        Thread.create tail proc_stderr
      else wait ()
    in
    wait ()

  let start ~process ?(args = [||]) ~message () =
    let server_process =
      Unix.open_process_args_full process args (Unix.environment ())
    in
    let server_pid = Unix.process_full_pid server_process in
    (* 2: wait until the server is ready *)
    let thread = wait_until_ready ~message server_process in
    { thread; server_pid; server_process }

  let stop { thread; server_pid; server_process } =
    Unix.kill server_pid Sys.sigterm;
    Unix.close_process_full server_process |> ignore;
    Thread.join thread
end

module KeyfenderApp : BACKEND = struct
  type ctx = unit

  let init () = ()
  let finish () = ()

  type t = UnixApp.t

  let start () =
    UnixApp.start
      ~process:"../../../keyfender/_build/default/test/test_server.exe"
      ~message:"listening on 8080" ()

  let stop = UnixApp.stop
end

module KeyfenderUnikernel : BACKEND = struct
  type ctx = {
    etcd_pid : int;
    etcd_process : in_channel * out_channel * in_channel;
    log_thread : Thread.t;
  }

  type t = UnixApp.t

  let init () =
    let open Bos.OS in
    let run_dir = Fpath.v "../../run" in
    let etcd_dir = Fpath.(run_dir / "default.etcd") in
    Dir.create etcd_dir |> Result.get_ok |> ignore;

    let etcd_process =
      Unix.open_process_args_full "../../etcd-download/etcd"
        [|
          "etcd";
          "--log-level=warn";
          "--max-txn-ops";
          "512";
          "--data-dir";
          Fpath.to_string etcd_dir;
        |]
        (Unix.environment ())
    in
    let etcd_pid = Unix.process_full_pid etcd_process in
    let _, _, proc_stderr = etcd_process in
    let th = Thread.create UnixApp.tail proc_stderr in
    { etcd_pid; log_thread = th; etcd_process }

  let finish { etcd_pid; etcd_process; log_thread } =
    Unix.kill etcd_pid Sys.sigterm;
    Unix.close_process_full etcd_process |> ignore;
    Thread.join log_thread

  let start () =
    let open Bos.OS in
    (Cmd.run
    @@ Bos.Cmd.(
         v "../../../../etcd-download/etcdctl" % "del" % "" % "--from-key=true")
    )
    |> Result.get_ok;
    UnixApp.start ~process:"../../../s_keyfender/dist/keyfender"
      ~args:
        [|
          "keyfender";
          "--platform=127.0.0.1";
          "--http=8080";
          "--https=8443";
          "--start";
        |]
      ~message:"listening on 8443/TCP for HTTPS" ()

  let stop t = UnixApp.stop t
end

(* execute [fn] with current working directory changed to [directory] *)
let in_dir directory fn =
  let old = Unix.getcwd () in
  Unix.chdir directory;
  Fun.protect ~finally:(fun () -> Unix.chdir old) fn

(* list the content of [dir], excluding dot files *)
let ls dir =
  let dir = Unix.opendir dir in
  let rec ls dirs =
    match Unix.readdir dir with
    | dirname when dirname.[0] = '.' -> ls dirs
    | dirname -> ls (dirname :: dirs)
    | exception End_of_file ->
        Unix.closedir dir;
        dirs
  in
  ls [] |> List.sort String.compare

let ( let* ) = Result.bind
let ( let+ ) a f = Result.map f a
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
  List.find_map
    (fun line ->
      if Astring.String.is_prefix ~affix:"HTTP" line then
        match String.split_on_char ' ' line with
        | _ :: code :: _ -> Some code
        | _ -> None
      else None)
    content
  |> Option.to_result ~none:(`Msg ("actual_code of " ^ Fpath.to_string file))

(*
extract the expected code from the file name:

expected_code "400_wrong_json_headers.out" => "400" *)
let expected_code v =
  match String.split_on_char '_' v with
  | code :: _ -> Ok code
  | _ -> Error (`Msg "expected_code: unknown")

(* perform the API output test *)
let test_error test =
  let open Bos in
  let* () = OS.Cmd.run Cmd.(v ("./" ^ test ^ command_suffix)) in
  let headers_file = Fpath.v (test ^ "_headers.out") in
  let* actual_code = actual_code headers_file in
  let* expected_code = expected_code test in
  Alcotest.(check string) (test ^ ": code matches") expected_code actual_code;
  Ok ()

(* expected to be run from a "generated/XXX" folder, this function
   tests a specific endpoint. *)
let tests_endpoint (module B : BACKEND) () =
  (* 1: start the server*)
  let server = B.start () in
  Fun.protect ~finally:(fun () -> B.stop server) @@ fun () ->
  (* 3: perform endpoint-specific setup *)
  let () =
    Bos.(OS.Cmd.run Cmd.(v "./setup.sh")) |> function
    | Ok () -> ()
    | Error (`Msg e) -> Alcotest.fail ("setup: " ^ e)
  in
  Printf.printf "PWD: %s\n" (Unix.getcwd ());
  (* 4: perform error tests *)
  let () =
    ls "."
    |> List.filter_map (fun s ->
           if Astring.String.is_suffix ~affix:command_suffix s then
             Some String.(sub s 0 (length s - command_suffix_len))
           else None)
    |> List.map test_error
    |> List.iter (function
         | Ok () -> ()
         | Error (`Msg msg) -> Alcotest.fail msg)
  in
  (* 5: perform happy-path test *)
  let () =
    if Bos.OS.Path.exists (Fpath.v "cmd.sh") |> Result.get_ok then
      (let* () = Bos.(OS.Cmd.run Cmd.(v "./cmd.sh")) in
       let* expected_code = actual_code Fpath.(v "headers.expected") in
       let* actual_code = actual_code Fpath.(v "headers.out") in
       Alcotest.(check string) "CMD: code matches" expected_code actual_code;
       let* skip = Bos.OS.Path.exists Fpath.(v "body.skip") in
       if not skip then
         let* expected_body =
           Bos.OS.File.read_lines Fpath.(v "body.expected")
         in
         let+ actual_body = Bos.OS.File.read_lines Fpath.(v "body.out") in
         Alcotest.(check (list string))
           "CMD: body matches" expected_body actual_body
       else Ok ())
      |> function
      | Ok () -> ()
      | Error (`Msg msg) -> Alcotest.fail msg
  in
  (* 6: server tear down *)
  Bos.(OS.Cmd.run Cmd.(v "./shutdown.sh")) |> ignore

let tests_of_dir (module B : BACKEND) dir prefix =
  ls dir
  |> List.map (fun endpoint ->
         ( prefix ^ ":" ^ endpoint,
           [
             ( Alcotest.test_case "OK" `Quick @@ fun () ->
               in_dir (dir ^ "/" ^ endpoint) (tests_endpoint (module B)) );
           ] ))

let api_tests backend = tests_of_dir backend "generated" "API"
let custom_tests backend = tests_of_dir backend "load" "LOAD"
let tests backend = api_tests backend @ custom_tests backend

let main (module B : BACKEND) =
  let ctx = B.init () in
  try
    Fun.protect ~finally:(fun () -> B.finish ctx) @@ fun () ->
    Alcotest.run ~and_exit:false ~argv:Sys.argv "unikernel" (tests (module B))
  with Alcotest.Test_error -> exit 1

let () = main (module KeyfenderUnikernel)
