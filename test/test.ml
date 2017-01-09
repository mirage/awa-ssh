(*
 * Copyright (c) 2016 Christiano F. Haesbaert <haesbaert@haesbaert.org>
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

let printf = Printf.printf

let tty_out = Unix.isatty Unix.stdout
let colored_or_not cfmt fmt =
  if tty_out then (Printf.sprintf cfmt) else (Printf.sprintf fmt)
let red fmt    = colored_or_not ("\027[31m"^^fmt^^"\027[m") fmt
let green fmt  = colored_or_not ("\027[32m"^^fmt^^"\027[m") fmt
let yellow fmt = colored_or_not ("\027[33m"^^fmt^^"\027[m") fmt
let blue fmt   = colored_or_not ("\027[36m"^^fmt^^"\027[m") fmt

let assert_failure x =
  let ok = try
      ignore @@ x ();
      false
    with
      Failure _ -> true
  in
  if not ok then
    failwith "Expected failure exception."

let assert_invalid x =
  let ok = try
      ignore @@ x ();
      false
    with
      Invalid_argument _ -> true
  in
  if not ok then
    invalid_arg "Expected failure exception."

let t_banner () =
  let open Ssh_trans in
  let c = make () in
  let good_strings = [
    "SSH-2.0-foobar lalal\r\n";
    "\r\n\r\nSSH-2.0-foobar lalal\r\n";
    "SSH-2.0-foobar lalal lololo\r\n";
    "SSH-2.0-OpenSSH_6.9\r\n";
    "Some crap before\r\nSSH-2.0-OpenSSH_6.9\r\n";
    "SSH-2.0-OpenSSH_6.9\r\nSomeCrap After\r\n";
  ]
  in
  List.iter (fun s ->
      let c = add_buf c (Cstruct.of_string s) |> handle in
      assert (c.state = Ssh_trans.Key_exchange))
    good_strings;
  let bad_strings = [
    "SSH-2.0\r\n";
    "SSH-1.0-foobar lalal lololo\r\n";
    "SSH-2.0-Open-SSH_6.9\r\n";
    "Some crap before\r\nSSH-2.0-Open-SSH_6.9\r\n";
    "\r\nSSH-2.0-Open-SSH_6.9\r\nSom crap after";
  ]
  in
  List.iter (fun s ->
      assert_invalid @@
      fun () -> add_buf c (Cstruct.of_string s) |> handle)
    bad_strings;
  (* Check if we can extract client_version *)
  let cx = add_buf c (Cstruct.of_string "SSH-2.0-OpenSSH_6.9\r\n") |> handle in
  assert (cx.peer_version = "OpenSSH_6.9");
  assert (Cstruct.len (cx.buffer) = 0);
  (* If we have multiple lines, check if we consume the buffer correctly *)
  let cx = add_buf c
      (Cstruct.of_string "Foo bar\r\nSSH-2.0-OpenSSH_6.9\r\n") |> handle
  in
  assert (cx.peer_version = "OpenSSH_6.9");
  assert (Cstruct.len (cx.buffer) = 0);
  let cx = add_buf c
      (Cstruct.of_string "Foo bar\r\nSSH-2.0-OpenSSH_6.9\r\nLALA") |> handle
  in
  assert (cx.peer_version = "OpenSSH_6.9");
  assert (Cstruct.len (cx.buffer) = 4)

let t_key_exchange () =
  let open Ssh_trans in
  let open Ssh_wire in
  let c = { (make ()) with state = Key_exchange } in

  (* Make sure nothing happens if packet is incomplete *)
  let cx = add_buf c (Cstruct.of_string "1") in
  assert (cx = (cx |> handle));
  (*
   * Case 1: A buffer with 64 bytes and payload with 60 bytes;
   * The header is 5 bytes, so a payload of 60 + 5 requires 65 bytes,
   * which means, this is an incomplete packet, nothing changes.
   *)
  let buf = Cstruct.create 64 in
  set_pkt_hdr_pkt_len buf 60l;
  set_pkt_hdr_pad_len buf 0;
  let cx = add_buf c buf in
  assert (cx = (cx |> handle));
  (*
   * Case 2: Same thing as 1, but with a 65 byte buffer,
   * this should consume the whole buffer
   *)
  (* XXX TODO fix me, now kex is complete and this naturaly fails. *)
  (* let buf = Cstruct.create 65 in *)
  (* Cstruct.set_uint8 buf 5 (message_id_to_int SSH_MSG_KEXINIT); *)
  (* set_pkt_hdr_pkt_len buf 60l; *)
  (* set_pkt_hdr_pad_len buf 0; *)
  (* let cx = add_buf c buf in *)
  (* let cy = handle cx in *)
  (* assert (cx <> cy); *)
  (* assert ((Cstruct.len cy.buffer) = 0); *)

  (* Read a pcap file and see if it makes sense. *)
  let file = "test/kex.packet" in
  let fd = Unix.(openfile file [O_RDONLY] 0) in
  let buf = Unix_cstruct.of_fd fd in
  let pkt = Cstruct.shift buf 5 |> kex_of_buf in
  (* printf "%s\n%!" (Sexplib.Sexp.to_string_hum (sexp_of_kex_pkt pkt)); *)
  Unix.close fd;

  (* Test a zero pkt_len *)
  let () = assert_invalid @@ fun () ->
    let buf = Cstruct.create 64 in
    set_pkt_hdr_pkt_len buf 0l;
    ignore @@ (add_buf c buf |> handle)
  in

  (* Test a pad_len equal/greater than pkt_len *)
  let () = assert_invalid @@ fun () ->
    let buf = Cstruct.create 64 in
    set_pkt_hdr_pkt_len buf 20l;
    set_pkt_hdr_pad_len buf 20;
    ignore @@ (add_buf c buf |> handle);
    ignore @@ (add_buf c buf |> handle);
  in
  ()

let t_namelist () =
  let open Ssh_trans in
  let open Ssh_wire in
  let s = ["uncle";"henry";"is";"evil"] in
  let buf = buf_of_nl s in
  assert (Cstruct.len buf = (4 + String.length (String.concat "," s)));
  assert (s = fst (nl_of_buf buf 0))

let run_test test =
  let f = fst test in
  let name = snd test in
  printf "%s %-40s%!" (blue "%s" "Test") (yellow "%s" name);
  let () = try f () with
      exn -> printf "%s\n%!" (red "failed");
      raise exn
  in
  printf "%s\n%!" (green "ok")

let all_tests = [
  (t_banner, "version banner");
  (t_key_exchange, "key exchange");
  (t_namelist, "namelist conversions");
]

let _ =
  List.iter run_test all_tests;
