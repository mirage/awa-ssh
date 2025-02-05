(*
 * Copyright (c) 2019 Hannes Mehnert <hannes@mehnert.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *)

let () = Printexc.record_backtrace true

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
    Logs.debug (fun m -> m "read %d bytes" (Cstruct.length cbuf));
    cbuf

let write_cstruct fd buf =
  let len = Cstruct.length buf in
  let bytes = Bytes.create len in
  Cstruct.blit_to_bytes buf 0 bytes 0 len;
  let n = Unix.write fd bytes 0 len in
  assert (n > 0)

let jump _ user pass seed typ keyfile authenticator host port =
  let ( let* ) = Result.bind in
  Mirage_crypto_rng_unix.use_default ();
  let fd = Unix.(socket PF_INET SOCK_STREAM 0) in
  Unix.(connect fd (ADDR_INET (inet_addr_of_string host, port)));
  match
    let* auth = match pass with
      | None ->
        let* key =
          match keyfile with
          | None -> Ok (Keys.of_seed typ seed)
          | Some f ->
            let fd = Unix.(openfile f [O_RDONLY] 0) in
            let file_buf = Unix_cstruct.of_fd fd in
            let r = match Wire.privkey_of_openssh file_buf, Wire.privkey_of_pem (Cstruct.to_string file_buf) with
              | Ok (k, _), _ -> Ok k
              | _, Ok k -> Ok k
              | Error m, _ -> Error m
            in
            Unix.close fd;
            r
        in
        Logs.info (fun m -> m "using publickey authentication");
        Ok (`Pubkey key)
      | Some pass ->
        Logs.info (fun m -> m "using password authentication");
        Ok (`Password pass)
    in
    let* authenticator = Keys.authenticator_of_string authenticator in
    let t, out = Client.make ~authenticator ~user auth in
    List.iter (write_cstruct fd) out;
    let rec read_react t =
      let data = read_cstruct fd in
      let now = Mtime_clock.now () in
      let* t, replies, events = Client.incoming t now data in
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

let pass =
  let doc = "password" in
  Arg.(value & opt (some string) None & info [ "password" ] ~doc)

let seed =
  let doc = "private key seed" in
  Arg.(value & opt string "180586" & info [ "seed" ] ~doc)

let keytype =
  let doc = "private key type" in
  Arg.(value & opt (enum [ ("rsa", `Rsa) ; ("ed25519", `Ed25519) ]) `Rsa & info [ "keytype" ] ~doc)

let keyfile =
  let doc = "private key file" in
  Arg.(value & opt (some file) None & info [ "key" ] ~doc)

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
  let term =
    Term.(term_result (const jump $ setup_log $ user $ pass $ seed $ keytype $ keyfile $ authenticator $ host $ port))
  and info =
    Cmd.info "awa_test_client" ~version:"%%VERSION_NUM"
  in
  Cmd.v info term

let () = exit (Cmd.eval cmd)
