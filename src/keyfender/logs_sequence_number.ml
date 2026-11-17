(* Copyright 2023 - 2023, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

let reporter base =
  let v = ref 0 in
  {
    Logs.report =
      (fun src level ~over k msgf ->
        (* one number per report, even if the base reporter calls msgf twice *)
        incr v;
        let n = !v in
        let msgf fn =
          let fn ?header ?tags format =
            fn ?header ?tags ("[%d] " ^^ format) n
          in
          msgf fn
        in
        base.Logs.report src level ~over k msgf);
  }
