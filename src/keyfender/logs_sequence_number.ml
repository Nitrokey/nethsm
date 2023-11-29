(* Copyright 2023 - 2023, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

let reporter base =
  let v = ref 0 in
  {
    Logs.report =
      (fun src level ~over k msgf ->
        let msgf fn =
          let fn ?header ?tags format =
            incr v;
            fn ?header ?tags ("[%d] " ^^ format) !v
          in
          msgf fn
        in
        base.Logs.report src level ~over k msgf);
  }
