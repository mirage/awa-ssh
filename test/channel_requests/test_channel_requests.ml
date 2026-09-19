open Awa

let now = Mtime_clock.now ()

(* OpenSSH sends keepalive@openssh.com as a channel request whenever a channel
   is open, and a name we do not recognise must still parse rather than error. *)
let channel_request_parsing () =
  let request name want_reply =
    let b = Buffer.create 32 in
    Wire.put_message_id b Ssh.MSG_CHANNEL_REQUEST;
    Wire.put_uint32 b 0l;
    Wire.put_string b name;
    Wire.put_bool b want_reply;
    Result.get_ok (Wire.get_message (Buffer.contents b))
  in
  assert (request "keepalive@openssh.com" true =
          Ssh.Msg_channel_request (0l, true, Ssh.Keepalive));
  assert (request "madeup@nonexistent.com" false =
          Ssh.Msg_channel_request
            (0l, false, Ssh.Unknown ("madeup@nonexistent.com", "")))

(* RFC 4254 5.4: the reply names the channel by the peer's number for it, not
   ours.  And once we have sent a close we stop answering on that channel. *)
let channel_request_replies () =
  let priv, _ = Mirage_crypto_ec.Ed25519.generate () in
  let t, _ = Server.make (Hostkey.Ed25519_priv priv) in
  let c, channels =
    Result.get_ok (Channel.add ~id:7l ~win:4096l ~max_pkt:4096l Channel.empty_db)
  in
  let t = Server.{ t with channels; expect = None } in
  let request = Ssh.Msg_channel_request (Channel.id c, true, Ssh.Keepalive) in
  assert (Channel.their_id c = 7l && Channel.id c = 0l);
  let _, replies, _ = Result.get_ok (Server.input_msg t request now) in
  assert (replies = [ Ssh.Msg_channel_failure (Channel.their_id c) ]);
  let closed = Channel.{ c with state = Sent_close } in
  let sent_close = Server.{ t with channels = Channel.update closed t.channels } in
  let _, replies, _ = Result.get_ok (Server.input_msg sent_close request now) in
  assert (replies = [])

(* A request naming a channel we do not have.  RFC 4254 5.3 permits reusing a
   number once both ends have closed it, so this may be a race, but we follow
   OpenSSH's server and disconnect. *)
let unknown_channel () =
  let priv, _ = Mirage_crypto_ec.Ed25519.generate () in
  let t, _ = Server.make (Hostkey.Ed25519_priv priv) in
  let t = Server.{ t with expect = None } in
  let request = Ssh.Msg_channel_request (0l, true, Ssh.Keepalive) in
  match Result.get_ok (Server.input_msg t request now) with
  | _, [ Ssh.Msg_disconnect _ ], Some (Server.Disconnected _) -> ()
  | _ -> failwith "expected a disconnect for a request on an unknown channel"

let direct_tcpip_open () =
  let b = Buffer.create 64 in
  Wire.put_message_id b Ssh.MSG_CHANNEL_OPEN;
  Wire.put_string b "direct-tcpip";
  Wire.put_uint32 b 3l;
  Wire.put_uint32 b 4096l;
  Wire.put_uint32 b 1024l;
  Wire.put_string b "example.com";
  Wire.put_uint32 b 80l;
  Wire.put_string b "127.0.0.1";
  Wire.put_uint32 b 54321l;
  assert (Result.get_ok (Wire.get_message (Buffer.contents b)) =
          Ssh.Msg_channel_open
            (3l, 4096l, 1024l,
             Ssh.Direct_tcpip ("example.com", 80l, "127.0.0.1", 54321l)))

let () =
  Mirage_crypto_rng_unix.use_default ();
  channel_request_parsing ();
  channel_request_replies ();
  unknown_channel ();
  direct_tcpip_open ()
