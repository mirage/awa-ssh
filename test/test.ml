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
open Printf

let tty_out = Unix.isatty Unix.stdout && Unix.getenv "TERM" <> "dumb"
let colored_or_not cfmt fmt =
  if tty_out then sprintf cfmt else sprintf fmt
let red fmt    = colored_or_not ("\027[31m"^^fmt^^"\027[m") fmt
let green fmt  = colored_or_not ("\027[32m"^^fmt^^"\027[m") fmt
let yellow fmt = colored_or_not ("\027[33m"^^fmt^^"\027[m") fmt
let blue fmt   = colored_or_not ("\027[36m"^^fmt^^"\027[m") fmt

let cipher_key_of cipher key iv =
  let open Nocrypto.Cipher_block.AES in
  let open Cipher in
  match cipher with
  | Plaintext -> { cipher = Plaintext;
                   cipher_key = Plaintext_key;
                   cipher_iv = iv}
  | Aes128_ctr | Aes192_ctr | Aes256_ctr ->
    { cipher;
      cipher_key = Aes_ctr_key (CTR.of_secret key);
      cipher_iv = iv}
  | Aes128_cbc | Aes192_cbc | Aes256_cbc ->
    { cipher;
      cipher_key = Aes_cbc_key (CBC.of_secret key);
      cipher_iv = iv}

let hmac_key_of hmac key = Hmac.{ hmac; key; seq = Int32.zero }

let encrypt_plain msg =
  fst (Packet.encrypt Kex.plaintext_keys msg)

let decrypt_plain buf =
  match Packet.decrypt Kex.plaintext_keys buf with
  | Ok (Some (pkt, buf, _)) -> ok (Some (pkt, buf))
  | Ok None -> ok None
  | Error e -> error e

(* let assert_ok x = assert (is_ok x) *)

let assert_error x = assert (is_error x)

let assert_none = function None -> () | _ -> failwith "Expected None"

let assert_false x = assert (not x)

let get_some = function None -> failwith "Expected Some" | Some x -> x

let timeout s =
  let left = Unix.alarm s in
  if s <> 0 && left <> 0 then
    failwith "Timeout already pending"

let t_banner () =
  let good_strings = [
    "SSH-2.0-foobar lalal\r\n";
    "\r\n\r\nSSH-2.0-foobar lalal\r\n";
    "SSH-2.0-foobar lalal lololo\r\n";
    "SSH-2.0-OpenSSH_6.9\r\n";
    "Some crap before\r\nSSH-2.0-OpenSSH_6.9\r\n";
    "SSH-2.0-OpenSSH_6.9\r\nSomeCrap After\r\n";
    "SSH-2.0-OpenSSH_7.4p1 Debian-6-lala-lolo\r\n";
  ]
  in
  List.iter (fun s ->
      match Wire.get_version (Cstruct.of_string s) with
      | Ok (Some s, _) -> ()
      | Ok (None, _) -> failwith "expected some"
      | Error e -> failwith e)
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
      match Wire.get_version (Cstruct.of_string s) with
      | Ok (Some _, _) -> failwith "expected none or error"
      | Ok (None, _) -> ()
      | Error e -> ())
    bad_strings

let t_parsing () =
  let open Ssh in
  (*
   * Case 1: Full buff consumed
   *)
  let msg = Msg_ignore "a" in
  let buf = encrypt_plain msg in
  let pkt, rbuf = get_some @@ get_ok @@ decrypt_plain buf in
  let msg2 = get_ok @@ Packet.to_msg pkt in
  assert (msg = msg2);
  assert ((Cstruct.len rbuf) = 0);

  (*
   * Case 2: 1 byte left
   *)
  let msg = Msg_ignore "a" in
  let buf, _ = Packet.encrypt Kex.plaintext_keys msg in
  let buf = Cstruct.append buf (Cstruct.of_string "b") in
  let pkt, rbuf = get_some @@ get_ok @@ decrypt_plain buf in
  let msg2 = get_ok @@ Packet.to_msg pkt in
  assert (msg = msg2);
  assert ((Cstruct.len rbuf) = 1);

  (* Case 3: Test a zero pkt_len *)
  let buf = Cstruct.create 64 in
  set_pkt_hdr_pkt_len buf 0l;
  set_pkt_hdr_pad_len buf 0;
  let e = get_error (decrypt_plain buf) in
  assert (e = "decrypt: Bogus pkt len");

  let id msg =
    let buf = encrypt_plain msg in
    let pkt, buf = get_some @@ get_ok @@ decrypt_plain buf in
    let msg2 = get_ok @@ Packet.to_msg pkt in
    assert ((Cstruct.len buf) = 0);
    match msg, msg2 with
    (* Can't compare Cstruct.t, must unpack and Cstruct.equal () *)
    | Msg_userauth_request (user_a, service_a, authmethod_a),
      Msg_userauth_request (user_b, service_b, authmethod_b) ->
      assert ((user_a, service_a) = (user_b, service_b));
      assert (auth_method_equal authmethod_a authmethod_b);
    | Msg_kexdh_reply (pub_rsa1, mpint1, siga),
      Msg_kexdh_reply (pub_rsa2, mpint2, sigb) ->
      assert (pub_rsa1 = pub_rsa2 && mpint1 = mpint2);
      assert (Hostkey.signature_equal siga sigb)
    | Msg_channel_open_confirmation (a1, a2, a3, a4, a5),
      Msg_channel_open_confirmation (b1, b2, b3, b4, b5) ->
      assert (a1 = b1);
      assert (a2 = b2);
      assert (a3 = b3);
      assert (a4 = b4);
      assert (Cstruct.equal a5 b5);
    | Msg_channel_request (a1, a2, Raw_data a3),
      Msg_channel_request (b1, b2, Raw_data b3) ->
      assert (a1 = b1);
      assert (a2 = b2);
      assert (Cstruct.equal a3 b3);
    | msg, msg2 -> assert (msg = msg2)
  in
  let long = Int32.of_int 180586 in
  let mpint = Nocrypto.Numeric.Z.of_int 180586 in
  let cstring = Cstruct.of_string "The Conquest of Bread" in
  (* XXX slow *)
  let rsa = Nocrypto.Rsa.(generate 2048) in
  let priv_rsa = Hostkey.Rsa_priv rsa in
  let pub_rsa = Hostkey.Rsa_pub (Nocrypto.Rsa.pub_of_priv rsa) in
  let signature = Hostkey.sign priv_rsa cstring in
  let l =
    [ Msg_disconnect (DISCONNECT_PROTOCOL_ERROR, "foo", "bar");
      Msg_ignore "Fora Temer";
      Msg_unimplemented long;
      Msg_debug (false, "Fora", "Temer");
      Msg_service_request "Fora Temer";
      Msg_service_accept "Ricardo Flores Magon";
      (* Msg_kexinit foo; *)
      Msg_kexdh_init mpint;
      Msg_kexdh_reply (pub_rsa, mpint, signature);
      Msg_newkeys;
      Msg_userauth_request
        ("haesbaert", "ssh-userauth",
         Pubkey (pub_rsa, None));
      Msg_userauth_request
        ("haesbaert", "ssh-userauth",
         Pubkey (pub_rsa, Some signature));
      Msg_userauth_request
        ("haesbaert", "ssh-userauth",
         Password ("a", Some "b"));
      Msg_userauth_request
        ("haesbaert", "ssh-userauth",
         Password ("a", None));
      Msg_userauth_request
        ("haesbaert", "ssh-userauth",
         Hostbased ("a", (Cstruct.of_string "b"), "c", "d",
                    (Cstruct.of_string "e")));
      Msg_userauth_request
        ("haesbaert", "ssh-userauth", Authnone);
      Msg_userauth_failure (["Fora"; "Temer"], true);
      Msg_userauth_success;
      Msg_userauth_banner ("Fora", "Temer");
      Msg_userauth_pk_ok pub_rsa;
      Msg_global_request
        ("tcpip-forward", true,
        Tcpip_forward ("127.0.0.1", long));
      Msg_request_success (None);
      Msg_request_failure;
      Msg_channel_open
        (long, long, long,
         X11 ("::1", long));
      Msg_channel_open_confirmation
        (long, long, long, long, Cstruct.of_string "Freedom of Mind");
      Msg_channel_open_failure
        (long, long, "Because you stink", "enEN");
      Msg_channel_window_adjust (long, Int32.succ long);
      Msg_channel_data (long, "DATADATA");
      Msg_channel_extended_data (long, long, "DATADATA");
      Msg_channel_eof long;
      Msg_channel_close long;
      Msg_channel_request (long, false, Pty_req ("a", long, long, long, long, "b"));
      Msg_channel_request (long, false, X11_req (false, "a", "b", long));
      Msg_channel_request (long, false, Env ("a", "b"));
      Msg_channel_request (long, false, Shell);
      Msg_channel_request (long, false, Exec "a");
      Msg_channel_request (long, false, Subsystem "a");
      Msg_channel_request (long, false, Window_change (long, long, long, long));
      Msg_channel_request (long, false, Xon_xoff false);
      Msg_channel_request (long, false, Signal "a");
      Msg_channel_request (long, false, Exit_status long);
      Msg_channel_request (long, false, Exit_signal ("a", false, "b", "c"));
      (* It's illegal to serialize Raw_data for now *)
      (* Msg_channel_request (long, false, Raw_data (Cstruct.of_string "Hegel")); *)
      Msg_channel_success long;
      Msg_channel_failure long; ]
  in
  List.iter (fun m -> id m) l

let t_key_exchange () =
  (* Read a pcap file and see if it makes sense. *)
  let file = "test/kex.packet" in
  let fd = Unix.(openfile file [O_RDONLY] 0) in
  let buf = Unix_cstruct.of_fd fd in
  let pkt, rbuf = get_some @@ get_ok @@ decrypt_plain buf in
  let msg = get_ok @@ Packet.to_msg pkt in
  let () = match msg with
    | Ssh.Msg_kexinit kex ->
      (* printf "%s\n%!" (Sexplib.Sexp.to_string_hum (Ssh.sexp_of_kex_pkt kex)); *)
      ()
    | _ -> failwith "Expected Msg_kexinit"
  in
  Unix.close fd

let t_namelist () =
  let s = ["The";"Conquest";"Of";"Bread"] in
  let buf = Dbuf.to_cstruct @@ Wire.put_nl s (Dbuf.create ()) in
  assert (Cstruct.len buf = (4 + String.length (String.concat "," s)));
  assert (s = fst (get_ok (Wire.get_nl buf)))

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
  let mpint = fst @@ get_ok @@ Wire.get_mpint (Cstruct.append head data) in
  let buf = Nocrypto.Numeric.Z.to_cstruct_be mpint in
  assert ((Cstruct.len buf) = 2); (* Cuts the first two zeros *)
  assert_byte buf 0 0xff;
  assert_byte buf 1 0x02;

  (*
   * Case 2: Test identity
   *)
  assert (mpint =
          (fst @@ get_ok
             (Wire.get_mpint
                (Dbuf.to_cstruct @@
                      Wire.put_mpint mpint (Dbuf.create ())))));

  (*
   * Case 3: Test the other way from 1, one zero must be prepended
   * since the first byte is negative (0xff).
   *)
  let buf = Dbuf.to_cstruct @@ Wire.put_mpint mpint (Dbuf.create ()) in
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
  let e = get_error (Wire.get_mpint buf) in
  assert (e = "Negative mpint")

let t_version () =
  let t = Server.make (Hostkey.Rsa_priv (Nocrypto.Rsa.generate 2048)) [] in
  let client_version = "SSH-2.0-OpenSSH_6.9\r\n" in
  match Server.pop_msg2 t (Cstruct.of_string client_version) with
  | Error e -> failwith e
  | Ok (t, msg) ->
    match get_some msg with
    | Ssh.Msg_version v ->
      assert (v = "SSH-2.0-OpenSSH_6.9");
      let t, _ = get_ok (Server.input_msg t (Ssh.Msg_version v)) in
      assert (t.Server.client_version = (Some "SSH-2.0-OpenSSH_6.9"))
    | _ -> failwith "Expected Ssh_version"

let t_crypto () =
  let test keys =
    let open Kex in
    let txt = "abcdefghijklmnopqrstuvxz" in
    let msg = Ssh.Msg_ignore txt in
    let buf_enc, keys_next = Packet.encrypt keys msg in
    let pkt, buf, keys_next2 =
      get_some @@ get_ok @@ Packet.decrypt keys buf_enc
    in
    let msg = get_ok @@ Packet.to_msg pkt in
    let () = match msg with
      | Ssh.Msg_ignore s ->
        assert (s = txt)
      | _ -> failwith "bad msg"
    in
    assert ((Cstruct.len buf) = 0)
    (* Side effect below ! *)
    (* Nocrypto.Cipher_block.Counter.add16 keys.Kex.iv 0 Int64.(succ one); *)
    (* assert (Cstruct.equal keys.Kex.iv keys_next.Kex.iv); *)
    (* assert (Cstruct.equal keys.Kex.iv keys_next2.Kex.iv) *)
  in
  let make cipher hmac =
    let open Cipher in
    let secret = Cstruct.of_string "Pyotr Alexeyevich Kropotkin 1842" in
    let iv = Cstruct.set_len secret 16 in
    let cipher = cipher_key_of cipher secret iv in
    let mac = hmac_key_of hmac secret in
    Kex.{ cipher; mac; tx_rx = Int64.zero }
  in
  List.iter (fun cipher ->
      List.iter (fun hmac ->
          test (make cipher hmac))
        Hmac.preferred)
    Cipher.preferred

let t_openssh_pub () =
  let fd = Unix.(openfile "test/awa_test_rsa.pub" [O_RDONLY] 0) in
  let file_buf = Unix_cstruct.of_fd fd in
  let key = get_ok (Wire.pubkey_of_openssh file_buf) in
  let buf = Wire.openssh_of_pubkey key in
  assert (Cstruct.equal file_buf buf);
  Unix.close fd

let t_signature () =
  let priv = Hostkey.Rsa_priv (Nocrypto.Rsa.generate 2048) in
  let pub = Hostkey.pub_of_priv priv in
  let unsigned = Nocrypto.Rng.generate 128 in
  let signed = Hostkey.sign priv unsigned in
  assert (Hostkey.verify pub ~signed ~unsigned);
  (* Corrupt every one byte in the signature, all should fail *)
  for off = 0 to pred (Cstruct.len signed) do
    let evilbyte = Cstruct.get_uint8 signed off in
    Cstruct.set_uint8 signed off (succ evilbyte);
    assert_false (Hostkey.verify pub ~signed ~unsigned);
    Cstruct.set_uint8 signed off evilbyte;
  done

let t_ignore_next_packet () =
  let t = Server.make (Hostkey.Rsa_priv (Nocrypto.Rsa.generate 2048)) [] in
  let t = Server.{ t with client_version = Some "SSH-2.0-client";
                          expect = Some(Ssh.MSG_KEXINIT) }
  in
  let kexinit = Ssh.{ (Kex.make_kexinit()) with
                      encryption_algs_ctos = ["aes256-cbc"];
                      first_kex_packet_follows = true }
  in
  (* Should set ignore_next_packet since the guess of the client is wrong *)
  let message = Ssh.Msg_kexinit kexinit in
  let buf = encrypt_plain message in
  let t, message = get_ok (Server.pop_msg2 t buf) in
  let message = get_some message in
  let t, _ = get_ok (Server.input_msg t message) in
  assert (t.Server.ignore_next_packet = true);
  (* Should ignore the next packet since ignore_next_packet is true *)
  let message = Ssh.Msg_debug(true, "woop", "Look at me") in
  let buf = encrypt_plain message in
  let t, msg = get_ok (Server.pop_msg2 t buf) in
  assert (t.Server.ignore_next_packet = false);
  assert (msg = None);
  (* Should not ignore the packet which follows after *)
  let buf = encrypt_plain message in
  let t, msg = get_ok (Server.pop_msg2 t buf) in
  assert (t.Server.ignore_next_packet = false);
  assert (msg = Some message)

let t_openssh_client () =
  let s1 = "Georg Wilhelm Friedrich Hegel" in
  let s2 = "Karl Marx" in
  let ossh_cmd = "ssh -p 18022 awa@127.0.0.1 -i test/awa_test_rsa echo" in
  let awa_cmd = "./_build/test/unix_server.native" in
  let awa_args = Array.of_list [] in
  let null = Unix.openfile "/dev/null" [ Unix.O_RDWR ] 0o666 in
  ignore @@ Unix.system "pkill unix_server";
  let awa_pid = Unix.create_process awa_cmd awa_args null null null in
  Unix.sleepf 0.1;
  let ossh = Unix.open_process_full ossh_cmd (Unix.environment ()) in
  let ossh_out, ossh_in = match ossh with o, i, e -> o, i in
  output_string ossh_in s1;
  output_char ossh_in '\n';
  flush ossh_in;
  assert (input_line ossh_out = s1);
  output_string ossh_in s2;
  output_char ossh_in '\n';
  flush ossh_in;
  assert (input_line ossh_out = s2);
  ignore @@ Unix.kill awa_pid Sys.sigterm;
  ignore @@ Unix.close_process_full ossh;
  ignore @@ Unix.close null

let run_test test =
  let run () = timeout 5; (fst test) (); timeout 0 in
  let name = snd test in
  printf "%s %-40s%!" (blue "%s" "Test") (yellow "%s" name);
  let () = try run () with
      exn -> printf "%s\n%!" (red "failed");
      raise exn
  in
  printf "%s\n%!" (green "ok")

let all_tests = [
  (t_parsing, "basic parsing");
  (t_banner, "version banner");
  (t_key_exchange, "key exchange");
  (t_namelist, "namelist conversions");
  (t_mpint, "mpint conversions");
  (t_version, "version exchange");
  (t_crypto, "encrypt/decrypt");
  (t_openssh_pub, "OpenSSH public key format");
  (t_signature, "signatures");
  (t_ignore_next_packet, "ignore next packet");
  (t_openssh_client, "OpenSSH@awa_ssh echo server");
]

let _ =
  Nocrypto.Rng.reseed (Cstruct.of_string "180586");
  Sys.set_signal Sys.sigalrm (Sys.Signal_handle (fun _ -> failwith "timeout"));
  List.iter run_test all_tests;
