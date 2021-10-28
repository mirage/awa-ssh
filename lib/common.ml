open Util

let output_msg keys = function
  | Ssh.Msg_version v -> Cstruct.of_string (v ^ "\r\n"), keys
  | msg -> Packet.encrypt keys msg

let version buf =
  let* version, input_buffer = Wire.get_version buf in
  match version with
  | None -> Ok (None, input_buffer)
  | Some v ->
    let msg = Ssh.Msg_version v in
    Ok (Some msg, input_buffer)

let decrypt ?(ignore_packet = false) keys buf =
  let* p = Packet.decrypt keys buf in
  match p with
  | None -> Ok (keys, None, buf)
  | Some (pkt, input_buffer, keys) ->
    let* msg = Packet.to_msg pkt in
    Ok (keys, (if ignore_packet then None else Some msg), input_buffer)
