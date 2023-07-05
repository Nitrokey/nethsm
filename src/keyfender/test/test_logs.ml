(* Copyright 2023 - 2023, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

let () =
  Logs.set_level (Some Info);
  Logs.set_reporter (Keyfender.Logs_sequence_number.reporter (Logs_fmt.reporter ()));
  Logs.info (fun f -> f "This is a log message");
  Logs.warn (fun f -> f "This is a warning");
  Logs.info (fun f -> f "This is a third message")
