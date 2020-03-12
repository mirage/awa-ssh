(*
 * Copyright (c) 2019 Hannes Mehnert <hannes@mehnert.org>
 *
 * All rights reversed
 *)

let () = Printexc.record_backtrace true

open Rresult.R
open Awa

let read_cstruct fd =
  let len = Ssh.max_pkt_len in
  let buf = Bytes.create len in
  let n = Unix.read fd buf 0 len in
  if n = 0 then
    failwith "got EOF"
  else
    let cbuf = Cstruct.create n in
    Cstruct.blit_from_bytes buf 0 cbuf 0 n;
    Logs.debug (fun m -> m "read %d bytes" (Cstruct.len cbuf));
    cbuf

let write_cstruct fd buf =
  let len = Cstruct.len buf in
  let bytes = Bytes.create len in
  Cstruct.blit_to_bytes buf 0 bytes 0 len;
  let n = Unix.write fd bytes 0 len in
  assert (n > 0)

let jump _ user seed authenticator host port =
  Mirage_crypto_rng_unix.initialize ();
  let fd = Unix.(socket PF_INET SOCK_STREAM 0) in
  Unix.(connect fd (ADDR_INET (inet_addr_of_string host, port)));
  match
    Keys.authenticator_of_string authenticator >>= fun authenticator ->
    let t, out = Client.make ~authenticator ~user (Keys.of_seed seed) in
    List.iter (write_cstruct fd) out;
    let rec read_react t =
      let data = read_cstruct fd in
      let now = Mtime_clock.now () in
      Client.incoming t now data >>= fun (t, replies, events) ->
      List.iter (write_cstruct fd) replies;
      let t, cont = List.fold_left (fun (t, cont) -> function
          | `Established id ->
            begin match Client.outgoing_request t ~id (Ssh.Exec "ls\ /tmp/bla") with
              | Error e ->
                Logs.err (fun m -> m "couldn't request ls: %s" e) ; t, cont
              | Ok (t', data) -> write_cstruct fd data ; t', cont
            end
          | `Disconnected -> Unix.close fd ; t, false
          | `Channel_data (_, data) ->
            Logs.app (fun m -> m "channel data: %s" (Cstruct.to_string data)) ;
            t, cont
          | e ->
            Logs.info (fun m -> m "received event %a" Client.pp_event e) ;
            t, cont)
          (t, true) events
      in
      if cont then read_react t else Ok "disconnected"
    in
    read_react t
  with
  | Ok x -> Logs.app (fun m -> m "all good %s" x) ; Ok ()
  | Error msg -> Error (`Msg msg)

let setup_log style_renderer level =
  Fmt_tty.setup_std_outputs ?style_renderer ();
  Logs.set_level level;
  Logs.set_reporter (Logs_fmt.reporter ~dst:Format.std_formatter ())

open Cmdliner

let user =
  let doc = "username to use" in
  Arg.(value & opt string "hannes" & info [ "user" ] ~doc)

let seed =
  let doc = "private key seed" in
  Arg.(value & opt string "180586" & info [ "seed" ] ~doc)

let authenticator =
  let doc = "authenticator" in
  Arg.(value & opt string "" & info [ "authenticator" ] ~doc)

let host =
  let doc = "remote host" in
  Arg.(value & opt string "127.0.0.1" & info [ "host" ] ~doc)

let port =
  let doc = "remote port" in
  Arg.(value & opt int 22 & info [ "port" ] ~doc)

let setup_log =
  Term.(const setup_log
        $ Fmt_cli.style_renderer ()
        $ Logs_cli.level ())

let cmd =
  Term.(term_result (const jump $ setup_log $ user $ seed $ authenticator $ host $ port)),
  Term.info "awa_test_client" ~version:"%%VERSION_NUM"

let () = match Term.eval cmd with `Ok () -> exit 0 | _ -> exit 1
