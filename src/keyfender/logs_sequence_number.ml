let reporter base =
  let v = ref 0 in
  {
    Logs.report = fun src level ~over k msgf ->
      let msgf = fun fn ->
        let fn ?header ?tags format =
          incr v;
          fn ?header ?tags ("[%d] " ^^ format) !v
        in
        msgf fn
      in
      base.Logs.report src level ~over k msgf
  }
