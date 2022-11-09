let seq_tag = Logs.Tag.def "seq" Format.pp_print_int

let reporter base =
  let v = ref 0 in
  {
    Logs.report = fun src level ~over k msgf ->
      let msgf = fun fn ->
        let fn ?header ?tags =
          let tags = Option.value tags ~default:Logs.Tag.empty in
          let tags = Some (Logs.Tag.add seq_tag !v tags) in
          incr v;
          fn ?header ?tags
        in
        msgf fn
      in
      base.Logs.report src level ~over k msgf
  }