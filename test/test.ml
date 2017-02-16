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

open Rresult.R
open Awa

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
    failwith "Expected failure exception"

let assert_invalid x =
  let ok = try
      ignore @@ x ();
      false
    with
      Invalid_argument _ -> true
  in
  if not ok then
    invalid_arg "Expected failure exception"

let get_some = function None -> invalid_arg "Expected Some" | Some x -> x

let assert_none = function None -> () | _ -> invalid_arg "Expected None"

let get_ok_s = function
  | Ok x -> x
  | Error s -> invalid_arg s

let t_banner () =
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
      let buf = Cstruct.of_string s in
      match (Ssh.scan_version buf) with
      | Result.Ok Some _ -> ()
      | Result.Ok None -> failwith "expected some"
      | Result.Error e -> failwith e)
    good_strings;

  let bad_strings = [
    "SSH-2.0\r\n";
    "SSH-1.0-foobar lalal lololo\r\n";
    "SSH-2.0-Open-SSH_6.9\r\n";
    "Some crap before\r\nSSH-2.0-Open-SSH_6.9\r\n";
    "\r\nSSH-2.0-Open-SSH_6.9\r\nSom crap after";
    "SSH-2.0-partiallineomg";
  ]
  in
  List.iter (fun s ->
      let buf = Cstruct.of_string s in
      match (Ssh.scan_version buf) with
      | Result.Ok Some _ -> failwith "expected none or error"
      | Result.Ok None -> ()
      | Result.Error e -> ())
    bad_strings

let t_key_exchange () =
  (*
   * Case 1: A buffer with 64 bytes and payload with 60 bytes.
   * The pkt_len header is 4 bytes, so a payload of 60 + 4 requires 64 bytes,
   * which means, this is a complete packet, all should be consumed.
   *)

  let buf = Cstruct.create 64 in
  Ssh.set_pkt_hdr_pkt_len buf 60l;
  Ssh.set_pkt_hdr_pad_len buf 0;
  let pkt, clen = get_some @@ get_ok_s @@ Ssh.scan_pkt buf in
  assert (clen = 64);
  (*
   * Case 2: Similar to 1, but the packet is missing 1 byte.
   * This should not return a packet.
   *)
  let buf = Cstruct.create 63 in
  Ssh.set_pkt_hdr_pkt_len buf 60l;
  Ssh.set_pkt_hdr_pad_len buf 0;
  assert_none @@ get_ok_s @@ Ssh.scan_pkt buf;

  (* Read a pcap file and see if it makes sense. *)
  let file = "test/kex.packet" in
  let fd = Unix.(openfile file [O_RDONLY] 0) in
  let buf = Unix_cstruct.of_fd fd in
  let () = match (get_some @@ get_ok_s @@ Decode.scan_message buf) with
    | Ssh.Ssh_msg_kexinit kex -> (* get_ok_s @@ handle_kex Server kex; *)
      printf "%s\n%!" (Sexplib.Sexp.to_string_hum (Ssh.sexp_of_kex_pkt kex));
      ()
    | _ -> failwith "Expected Ssh_msg_kexinit"
  in
  Unix.close fd;

  (* Case 3: Test a zero pkt_len *)
  let buf = Cstruct.create 64 in
  Ssh.set_pkt_hdr_pkt_len buf 0l;
  Ssh.set_pkt_hdr_pad_len buf 0;
  let e = get_error (Ssh.scan_pkt buf) in
  assert (e = "Malformed packet")


let t_namelist () =
  let s = ["The";"Conquest";"Of";"Bread"] in
  let buf = Encode.(to_cstruct @@ add_nl s (create ())) in
  assert (Cstruct.len buf = (4 + String.length (String.concat "," s)));
  assert (s = fst (get_ok (Decode.decode_nl buf)))

let t_mpint () =
  let assert_byte buf off v =
    assert ((Cstruct.get_uint8 buf off) = v)
  in

  (*
   * Case 1: Make sure zeroes are stripped from the beggining.
   *)
  let head = Cstruct.create 4 in
  let data = Cstruct.create 4 in
  Cstruct.set_uint8 data 0 0x00;
  Cstruct.set_uint8 data 1 0x00;
  Cstruct.set_uint8 data 2 0xff;
  Cstruct.set_uint8 data 3 0x02;
  Cstruct.BE.set_uint32 head 0 (Int32.of_int (Cstruct.len data));
  let mpint = fst @@ get_ok_s @@ Decode.decode_mpint (Cstruct.append head data) in
  let buf = Nocrypto.Numeric.Z.to_cstruct_be mpint in
  assert ((Cstruct.len buf) = 2); (* Cuts the first two zeros *)
  assert_byte buf 0 0xff;
  assert_byte buf 1 0x02;

  (*
   * Case 2: Test identity
   *)
  assert (mpint =
          (fst @@ get_ok_s
             (Decode.decode_mpint
                (Encode.(to_cstruct @@
                      add_mpint mpint (create ()))))));

  (*
   * Case 3: Test the other way from 1, one zero must be prepended
   * since the first byte is negative (0xff).
   *)
  let buf = Encode.(to_cstruct @@ add_mpint mpint (create ())) in
  (* 4 for header + 1 zero prepended + 2 data*)
  assert ((Cstruct.len buf) = (4 + 1 + 2));
  assert_byte buf 0 0x00;
  assert_byte buf 1 0x00;
  assert_byte buf 2 0x00;
  assert_byte buf 3 0x03;
  assert_byte buf 4 0x00;
  assert_byte buf 5 0xff;
  assert_byte buf 6 0x02;

  (*
   * Case 4: Make sure negative are errors.
   *)
  Cstruct.set_uint8 buf 4 0x80;
  let e = get_error (Decode.decode_mpint buf) in
  assert (e = "Negative mpint")

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
  (t_mpint, "mpint conversions");
]

let _ =
  List.iter run_test all_tests;
