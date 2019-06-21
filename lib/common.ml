open Rresult.R

let output_msg keys = function
  | Ssh.Msg_version v -> Cstruct.of_string (v ^ "\r\n"), keys
  | msg -> Packet.encrypt keys msg

let version buf =
  Wire.get_version buf >>= fun (version, input_buffer) ->
  match version with
  | None -> Ok (None, input_buffer)
  | Some v ->
    let msg = Ssh.Msg_version v in
    Ok (Some msg, input_buffer)

let decrypt ?(ignore_packet = false) keys buf =
  Packet.decrypt keys buf >>= function
  | None -> ok (keys, None, buf)
  | Some (pkt, input_buffer, keys) ->
    Packet.to_msg pkt >>= fun msg ->
    ok (keys, (if ignore_packet then None else Some msg), input_buffer)
