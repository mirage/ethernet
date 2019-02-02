(*
 * Copyright (c) 2010-2011 Anil Madhavapeddy <anil@recoil.org>
 * Copyright (c) 2011 Richard Mortier <richard.mortier@nottingham.ac.uk>
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
 *
 *)
open Lwt.Infix

let src = Logs.Src.create "ethernet" ~doc:"Mirage Ethernet"
module Log = (val Logs.src_log src : Logs.LOG)

module Make(Netif : Mirage_net_lwt.S) = struct

  type 'a io = 'a Lwt.t
  type buffer = Cstruct.t
  type macaddr = Macaddr.t

  type error = Netif.error
  let pp_error = Netif.pp_error

  type t = {
    netif: Netif.t;
  }

  let mac t = Netif.mac t.netif
  let mtu t = Netif.mtu t.netif (* interface MTU excludes Ethernet header *)

  let input ~arpv4 ~ipv4 ~ipv6 t frame =
    let open Ethernet_packet in
    MProf.Trace.label "ethernet.input";
    let of_interest dest =
      Macaddr.compare dest (mac t) = 0 || not (Macaddr.is_unicast dest)
    in
    match Unmarshal.of_cstruct frame with
    | Ok (header, payload) when of_interest header.destination ->
      begin
        let open Ethernet_wire in
        match header.ethertype with
        | ARP -> arpv4 payload
        | IPv4 -> ipv4 payload
        | IPv6 -> ipv6 payload
      end
    | Ok _ -> Lwt.return_unit
    | Error s ->
      Log.debug (fun f -> f "dropping Ethernet frame: %s" s);
      Lwt.return_unit

  let proto_to_type = function
    | `ARP -> Ethernet_wire.ARP
    | `IPv4 -> Ethernet_wire.IPv4
    | `IPv6 -> Ethernet_wire.IPv6

  let write t ?src destination proto ?size payload =
    MProf.Trace.label "ethernet.write";
    let source = match src with None -> mac t | Some x -> x in
    let frame = Netif.allocate_frame ?size t.netif in
    Ethernet_packet.Marshal.into_cstruct
      { source ; destination ; ethertype = proto_to_type proto }
      frame ;
    let off = payload (Cstruct.shift frame Ethernet_wire.sizeof_ethernet) in
    let len = off + Ethernet_wire.sizeof_ethernet in
    assert (len <= Cstruct.len frame && len > 0) ;
    Netif.write t.netif (Cstruct.set_len frame len) >|= function
    | Ok () -> Ok ()
    | Error e ->
      Log.warn (fun f -> f "netif write errored %a" Netif.pp_error e) ;
      Error e

  let connect netif =
    MProf.Trace.label "ethernet.connect";
    let t = { netif } in
    Log.info (fun f -> f "Connected Ethernet interface %a" Macaddr.pp (mac t));
    Lwt.return t

  let disconnect t =
    Log.info (fun f -> f "Disconnected Ethernet interface %a" Macaddr.pp (mac t));
    Lwt.return_unit
end
