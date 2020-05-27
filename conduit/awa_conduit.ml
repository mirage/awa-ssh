open Conduit

module Make
    (Scheduler : Sigs.SCHEDULER)
    (Conduit : Conduit.S
                 with type input = Cstruct.t
                  and type output = Cstruct.t
                  and type +'a s = 'a Scheduler.t)
    (M : Mirage_clock.MCLOCK)
= struct
  let return x = Scheduler.return x
  let ( >>= ) x f = Scheduler.bind x f
  let ( >>| ) x f = x >>= fun x -> return (f x)
  let ( >>? ) x f = x >>= function
    | Ok x -> f x
    | Error _ as err -> return err

  let reword_error f = function
    | Ok _ as v -> v
    | Error err -> Error (f err)

  type 'flow protocol_with_ssh = {
    mutable ssh : Awa.Client.t ;
    mutable uid : int32 option ;
    mutable closed : closed ;
    raw : Cstruct.t ;
    flow : 'flow ;
    queue : (char, Bigarray.int8_unsigned_elt) Ke.Rke.t ;
  } and closed =
      | Exited of int32
      | Eof
      | None

  let is_close : closed -> bool = function
    | None -> false | _ -> true

  type endpoint =
    { authenticator : Awa.Keys.authenticator option
    ; user : string
    ; key : Awa.Hostkey.priv
    ; req : Awa.Ssh.channel_request }

  module Make_protocol
      (Flow : Sigs.PROTOCOL
                with type input = Conduit.input
                 and type output = Conduit.output
                 and type +'a s = 'a Scheduler.t) =
    struct
      type input = Conduit.input
      type output = Conduit.output
      type +'a s = 'a Conduit.s

      type nonrec endpoint = Flow.endpoint * endpoint

      type flow = Flow.flow protocol_with_ssh

      type error =
        [ `Flow of Flow.error
        | `SSH of string
        | `Closed_by_peer ]

      let pp_error : error Fmt.t = fun ppf -> function
        | `Flow err -> Flow.pp_error ppf err
        | `SSH err -> Fmt.string ppf err
        | `Closed_by_peer -> Fmt.string ppf "Closed by peer"

      let flow_error err = `Flow err

      let writev flow cs =
        let rec one v =
          if Cstruct.len v = 0 then return (Ok ())
          else Flow.send flow v >>? fun len ->
            one (Cstruct.shift v len)
        and go = function
          | [] -> return (Ok ())
          | x :: r -> one x >>? fun () -> go r in
        go cs

      let blit src src_off dst dst_off len =
        let src = Cstruct.to_bigarray src in
        Bigstringaf.blit src ~src_off dst ~dst_off ~len

      let write queue v =
        Ke.Rke.N.push queue ~blit ~length:Cstruct.len ~off:0 v

      let handle_event t = function
        | `Established uid -> t.uid <- Some uid
        | `Channel_data (uid, data) ->
          if Option.(fold ~none:false ~some:(Int32.equal uid) t.uid)
          then write t.queue data else ()
        | `Channel_eof uid ->
          if Option.(fold ~none:false ~some:(Int32.equal uid) t.uid)
          then t.closed <- Eof else ()
        | `Channel_exit_status (uid, n) ->
          if Option.(fold ~none:false ~some:(Int32.equal uid) t.uid)
          then t.closed <- Exited n else ()
        | `Disconnected -> t.uid <- None

      let rec handle t =
        Flow.recv t.flow t.raw >>| reword_error flow_error >>? function
        | `End_of_input ->
          t.uid <- None ;
          t.closed <- Eof ;
          return (Ok ())
        | `Input len ->
          let raw = Cstruct.sub t.raw 0 len in
          match t.uid, Awa.Client.incoming t.ssh (Mtime.of_uint64_ns (M.elapsed_ns ())) raw with
          | _, Error err -> return (Error (`SSH err))
          | None, Ok (ssh, out, events) ->
            List.iter (handle_event t) events ; t.ssh <- ssh ;
            writev t.flow out >>| reword_error flow_error >>? fun () ->
            if Option.is_none t.uid && not (is_close t.closed)
            then handle t else return (Ok ())
          | Some _, Ok (ssh, out, events) ->
            List.iter (handle_event t) events ; t.ssh <- ssh ;
            writev t.flow out >>| reword_error flow_error >>? fun () ->
            return (Ok ())

      let flow (edn, { authenticator; user; key; req; }) =
        Flow.flow edn >>| reword_error flow_error >>? fun flow ->
        let ssh, bufs = Awa.Client.make ?authenticator ~user key in
        let raw = Cstruct.create 0x1000 in
        let queue = Ke.Rke.create ~capacity:0x1000 Bigarray.Char in
        writev flow bufs >>| reword_error flow_error >>? fun () ->
        let t = { ssh; uid= None; closed= None; flow; raw; queue; } in
        handle t >>? fun () ->
        match t.uid with
        | None -> assert false
        | Some uid -> match Awa.Client.outgoing_request t.ssh ~id:uid req with
          | Error err -> return (Error (`SSH err))
          | Ok (ssh, out) ->
            t.ssh <- ssh ; writev flow [ out ] >>| reword_error flow_error >>? fun () ->
            return (Ok t)

      let blit src src_off dst dst_off len =
        let dst = Cstruct.to_bigarray dst in
        Bigstringaf.blit src ~src_off dst ~dst_off ~len

      let rec recv t raw =
        match Ke.Rke.N.peek t.queue with
        | [] ->
          if not (is_close t.closed)
          then handle t >>? fun () -> recv t raw
          else return (Ok `End_of_input)
        | _ ->
          let max = Cstruct.len raw in
          let len = min (Ke.Rke.length t.queue) max in
          Ke.Rke.N.keep_exn t.queue ~blit ~length:Cstruct.len ~off:0 ~len raw ;
          Ke.Rke.N.shift_exn t.queue len ;
          return (Ok (`Input len))

      let send t raw =
        if not (is_close t.closed)
        then return (Error `Closed_by_peer)
        else
          match Awa.Client.outgoing_data t.ssh raw with
          | Ok (ssh, out) ->
            writev t.flow out >>| reword_error flow_error >>? fun () ->
            t.ssh <- ssh ; return (Ok (Cstruct.len raw))
          | Error err ->
            return (Error (`SSH err))

      let close t =
        t.closed <- Eof ; Flow.close t.flow >>| reword_error flow_error
    end

  let protocol_with_ssh :
    type edn flow.
    key:edn Conduit.key ->
    flow Conduit.Witness.protocol ->
    (edn * endpoint) Conduit.key
    * flow protocol_with_ssh Conduit.Witness.protocol =
    fun ~key protocol ->
    match Conduit.impl_of_protocol ~key protocol with
    | Ok (module Flow) ->
      let module M = Make_protocol (Flow) in
      let k = Conduit.key (Fmt.strf "%s + ssh" (Conduit.name_of_key key)) in
      let p = Conduit.register_protocol ~key:k ~protocol:(module M) in
      (k, p)
    | Error _ -> invalid_arg "Invalid key"
end
