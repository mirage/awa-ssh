open Awa

let now = Mtime_clock.now ()

let encrypt_plain msg = fst (Packet.encrypt (Kex.make_plaintext ()) msg)

let decrypt_plain buf =
  match Packet.decrypt (Kex.make_plaintext ()) buf with
  | Ok (Some (pkt, _, _)) -> pkt
  | Ok None -> failwith "expected a packet"
  | Error e -> failwith e

let () =
  Mirage_crypto_rng_unix.use_default ();

  (* The server answers properly. *)
  let keepalive =
    Ssh.Msg_global_request ("keepalive@openssh.com", true, Ssh.Keepalive)
  in
  let priv, _ = Mirage_crypto_ec.Ed25519.generate () in
  let s, _ = Server.make (Hostkey.Ed25519_priv priv) in
  let s = Server.{ s with expect = None } in
  let _, replies, _ = Result.get_ok (Server.input_msg s keepalive now) in
  assert (replies = [ Ssh.Msg_request_failure ]);

  (* The client answers properly. *)
  let c, _ = Client.make ~user:"u" (`Password "p") in
  let c, _, _ = Result.get_ok (Client.incoming c now "SSH-2.0-peer\r\n") in
  let _, replies, _ =
    Result.get_ok (Client.incoming c now (encrypt_plain keepalive))
  in
  assert (List.length replies = 1);
  let pkt = decrypt_plain (String.concat "" replies) in
  assert (Result.get_ok (Packet.to_msg pkt) = Ssh.Msg_request_failure);

  (* An unknown global request (default case) with no payload (edge case).
     Covers the bug that caused keepalives to fail. *)
  let b = Buffer.create 32 in
  Wire.put_message_id b Ssh.MSG_GLOBAL_REQUEST;
  Wire.put_string b "madeup@nonexistent.com";
  Wire.put_bool b false;
  assert (Result.get_ok (Wire.get_message (Buffer.contents b)) =
          Ssh.Msg_global_request
            ("madeup@nonexistent.com", false, Ssh.Unknown_request ""))
