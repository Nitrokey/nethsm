(*
  To call:
    dune exec ./generate_raml_tests.exe
*)

(*
  Data structure:

type raml = { header ..;
  types ..;
  endpoints ..}

*)

let example = CCIO.with_in "../../docs/nitrohsm-api.raml" CCIO.read_all
  |> Yaml.of_string
  |> Stdlib.Result.get_ok
let () = Sexplib.Sexp.pp_hum Format.std_formatter @@ Yaml.sexp_of_value example
let (endpoints, metadata) = Ezjsonm.get_dict example |> List.partition (fun (key, _v) -> CCString.prefix ~pre:"/" key)

let types = List.assoc "types" metadata
