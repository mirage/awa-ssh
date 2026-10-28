open Awa

let sent out =
  List.fold_left
    (fun n -> function Ssh.Msg_channel_data (_, d) -> n + String.length d | _ -> n)
    0 out

(* Window credit from the peer is not a licence to send more than it covers:
   100 bytes of credit must buy 100 bytes, not the whole backlog. *)
let () =
  let us =
    Result.get_ok (Channel.make_end 0 Ssh.channel_win_len Ssh.channel_max_pkt_len)
  in
  let them = Result.get_ok (Channel.make_end 0 50 Ssh.channel_max_pkt_len) in
  let c = Channel.make ~us ~them in
  let c, out = Result.get_ok (Channel.output_data ~flush:false c (String.make 200 'x')) in
  assert (sent out = 50);
  assert (c.Channel.them.Channel.win = 0);
  assert (String.length c.Channel.tosend = 150);
  let c, out = Result.get_ok (Channel.adjust_window c 100) in
  assert (sent out = 100);
  assert (c.Channel.them.Channel.win = 0);
  assert (String.length c.Channel.tosend = 50);
  (* and the remainder once it is paid for *)
  let c, out = Result.get_ok (Channel.adjust_window c 50) in
  assert (sent out = 50);
  assert (c.Channel.them.Channel.win = 0);
  assert (String.length c.Channel.tosend = 0)
