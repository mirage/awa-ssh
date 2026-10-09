open Awa

let ( let* ) = Result.bind

let now = Mtime_clock.now ()

let channel ?(win = Ssh.channel_win_len) ?(max_pkt = Ssh.channel_max_pkt_len) () =
  let e = Result.get_ok (Channel.make_end 0 win max_pkt) in
  Channel.make ~us:e ~them:e

let deliver c data =
  match Channel.input_packet c data with
  | Ok (c, out, adjust) -> c, out, adjust
  | Error m -> failwith ("expected the packet to be delivered: " ^ m)

(* Data within the window is handed up whole and charged to the window.  Our
   max channel packet size is well below the window refill threshold, so we
   don't have to account for that. *)
let consumes_the_window () =
  assert (Ssh.channel_max_pkt_len
          <= Ssh.channel_win_len - Ssh.channel_win_adj_threshold);
  let c = channel () in
  let data = Mirage_crypto_rng.generate 32 in
  let c', out, adjust = deliver c data in
  assert (String.equal out data);
  assert (adjust = None);
  assert (c'.Channel.us.Channel.win = Ssh.channel_win_len - 32)

(* Once the window falls below the threshold it is refilled, and the peer is
   given a window update. *)
let replenishes_below_threshold () =
  let rec drain c n =
    let data = String.make Ssh.channel_max_pkt_len 'x' in
    let win_before = c.Channel.us.Channel.win in
    match deliver c data with
    | c, _, None ->
      assert (c.Channel.us.Channel.win = win_before - Ssh.channel_max_pkt_len);
      assert (c.Channel.us.Channel.win >= Ssh.channel_win_adj_threshold);
      drain c (succ n)
    | c, _, Some adjust ->
      let drained = win_before - Ssh.channel_max_pkt_len in
      assert (drained < Ssh.channel_win_adj_threshold);
      assert (adjust = Ssh.Msg_channel_window_adjust (0, Ssh.channel_win_len - drained));
      (* and we really did give ourselves the credit we announced *)
      assert (c.Channel.us.Channel.win = Ssh.channel_win_len);
      succ n
  in
  (* 4MB of window, 64KB packets: the 32nd packet takes us under 2MB. *)
  assert (drain (channel ()) 0 = 32)

(* A packet over the maximum we advertised ends the connection: that limit is
   fixed at channel open, so unlike a window overrun there is no in-flight
   state a peer could be racing, and exceeding it means it ignored a number we
   handed it. *)
let refuses_over_max_pkt () =
  let c = channel () in
  let data = String.make (Ssh.channel_max_pkt_len + 1) 'x' in
  assert (Result.is_error (Channel.input_packet c data))

(* A peer that writes past the window loses the connection, which is the
   common decision among SSH implementations, except for OpenSSH, which has
   a tolerance of 10% (this time, we don't follow their example). *)
let refuses_a_window_overrun () =
  let c = channel ~win:100 () in
  assert (Result.is_error (Channel.input_packet c (String.make 101 'x')))

(* Right up to the window is fine, though. *)
let accepts_exactly_the_window () =
  let c = channel ~win:100 () in
  let data = String.make 100 'x' in
  let c, out, _ = deliver c data in
  assert (String.equal out data);
  (* exhausted, so, as things are now, automatically refilled *)
  assert (c.Channel.us.Channel.win = Ssh.channel_win_len)

(* And the server says so rather than letting the transport vanish.*)
let server_disconnects_on_violation () =
  let priv, _ = Mirage_crypto_ec.Ed25519.generate () in
  let t, _ = Server.make (Hostkey.Ed25519_priv priv) in
  let c, channels =
    Result.get_ok (Channel.add ~id:7 ~win:4096 ~max_pkt:4096 Channel.empty_db)
  in
  let t = Server.{ t with channels; expect = None } in
  let oversized = String.make (Ssh.channel_max_pkt_len + 1) 'x' in
  let msg = Ssh.Msg_channel_data (Channel.id c, oversized) in
  match Result.get_ok (Server.input_msg t msg now) with
  | _, [ Ssh.Msg_disconnect (Ssh.DISCONNECT_PROTOCOL_ERROR, _, _) ],
    Some (Server.Disconnected _) -> ()
  | _ -> failwith "expected a protocol error disconnect"

(* The client has to do the same, but Client.t is abstract and input_msg is not
   exported, so the only way in is Client.incoming -- which means driving a real
   client to Established against a real server.  Copied from the channel request
   tests. FIXME: factor these out. *)

(* Feed [buf] to the server, answering userauth, and return the bytes it emits. *)
let rec server_drain server buf out =
  match Server.pop_msg2 server buf with
  | Ok (server, None, buf) -> Ok (server, buf, out)
  | Ok (server, Some msg, buf) ->
    let* server, replies, event = Server.input_msg server msg now in
    let* server, replies =
      match event with
      | Some (Server.Userauth (_, userauth)) ->
        let* server, reply = Server.accept_userauth server userauth () in
        Ok (server, replies @ [ reply ])
      | _ -> Ok (server, replies)
    in
    let* server, bytes =
      List.fold_left (fun acc m ->
          let* server, sofar = acc in
          let* server, b = Server.output_msg server m in
          Ok (server, sofar ^ b))
        (Ok (server, "")) replies
    in
    server_drain server buf (out ^ bytes)
  | Error e -> Error e

(* Returns the client, the server, and the channel number the client answers to. *)
let established_client () =
  let priv, _ = Mirage_crypto_ec.Ed25519.generate () in
  let server, greeting = Server.make (Hostkey.Ed25519_priv priv) in
  let* server, to_client =
    List.fold_left (fun acc m ->
        let* server, sofar = acc in
        let* server, b = Server.output_msg server m in
        Ok (server, sofar ^ b))
      (Ok (server, "")) greeting
  in
  let client, first = Client.make `No_authentication ~user:"u" (`Password "pw") in
  let rec pump client server to_client to_server n =
    if n = 0 then Error "client never reached Established" else
      let* server, to_server, more = server_drain server to_server "" in
      let to_client = to_client ^ more in
      let* client, out, events = Client.incoming client now to_client in
      let to_server = to_server ^ String.concat "" out in
      match List.find_map (function `Established id -> Some id | _ -> None) events with
      | Some id -> Ok (client, server, id)
      | None -> pump client server "" to_server (pred n)
  in
  pump client server to_client (String.concat "" first) 20

let client_disconnects_on_violation () =
  Result.get_ok
    (let* client, server, id = established_client () in
     let oversized = String.make (Ssh.channel_max_pkt_len + 1) 'x' in
     let* server, bytes =
       Server.output_msg server (Ssh.Msg_channel_data (id, oversized))
     in
     let* _client, replies, events = Client.incoming client now bytes in
     assert (events = [ `Disconnected ]);
     (* and what it sent back really is a protocol error: let the server parse it *)
     let* _server, msg, _ = Server.pop_msg2 server (String.concat "" replies) in
     (match msg with
      | Some (Ssh.Msg_disconnect (Ssh.DISCONNECT_PROTOCOL_ERROR, _, _)) -> ()
      | _ -> failwith "expected the client to send a protocol error disconnect");
     Ok ())

let () =
  Mirage_crypto_rng_unix.use_default ();
  consumes_the_window ();
  replenishes_below_threshold ();
  refuses_over_max_pkt ();
  refuses_a_window_overrun ();
  accepts_exactly_the_window ();
  server_disconnects_on_violation ();
  client_disconnects_on_violation ()
