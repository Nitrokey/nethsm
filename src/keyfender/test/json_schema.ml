open Keyfender

let schemas =
  [
    ("platform_data", Json.platform_data_jsonschema);
    ("local_conf", Json.local_conf_jsonschema);
    ("network", Json.network_jsonschema);
    ("diagnose_data", Json.diagnose_data_jsonschema);
  ]
  |> List.iter @@ fun (name, s) ->
     Out_channel.with_open_text (name ^ ".json") @@ fun ch ->
     let ppf = Format.formatter_of_out_channel ch in
     s
     |> Ppx_deriving_jsonschema_runtime.json_schema
          ~definitions:[ ("network_config", Json.network_config_jsonschema) ]
     |> Yojson.pretty_print ppf;
     Format.pp_print_flush ppf ()
