let pp_exec_header =
  let x = match Array.length Sys.argv with
  | 0 -> Filename.basename Sys.executable_name
  | _ -> Filename.basename Sys.argv.(0)
  in
  let pf = Format.fprintf in
  let pp_header ppf (l, h) =
    if l = Logs.App then (match h with None -> () | Some h -> pf ppf "[%s] " h) else
    match h with
    | None -> pf ppf "%s: [%a] " x Logs.pp_level l
    | Some h -> pf ppf "%s: [%s] " x h
  in
  pp_header

let base_reporter
  ?(pp_header = pp_exec_header)
  ?(app = Format.std_formatter)
  ?(dst = Format.err_formatter) ()
  =
  let report _src level ~over k msgf =
    let k _ = over (); k () in
    msgf @@ fun ?header ?tags fmt ->
    let ppf = if level = Logs.App then app else dst in
    let tags = Option.value ~default:Logs.Tag.empty tags in
    Format.kfprintf k ppf ("%a %a@[" ^^ fmt ^^ "@]@.") Logs.Tag.pp_set tags pp_header (level, header)
  in
  { Logs.report }

let () =
  Logs.set_level (Some Info);
  Logs.set_reporter (Keyfender.Logs_sequence_number.reporter (base_reporter ()));
  Logs.info (fun f -> f "This is a log message");
  Logs.warn (fun f -> f "This is a warning");
  Logs.info (fun f -> f "This is a third message")
