type t = {
  source : Macaddr.t;
  destination : Macaddr.t;
  ethertype : Ethernet_wire.ethertype;
}

type error = string

let pp fmt t =
  Format.fprintf fmt "%a -> %a: %s" Macaddr.pp t.source
    Macaddr.pp t.destination (Ethernet_wire.ethertype_to_string t.ethertype)

let equal {source; destination; ethertype} q =
  (Macaddr.compare source q.source) = 0 &&
  (Macaddr.compare destination q.destination) = 0 &&
  Ethernet_wire.(compare (ethertype_to_int ethertype) (ethertype_to_int q.ethertype)) = 0

module Unmarshal = struct

  let of_cstruct frame =
    let open Ethernet_wire in
    if Cstruct.len frame >= sizeof_ethernet then
      match get_ethernet_ethertype frame |> int_to_ethertype with
      | None -> Error (Printf.sprintf "unknown ethertype 0x%x in frame"
                                (get_ethernet_ethertype frame))
      | Some ethertype ->
        let payload = Cstruct.shift frame sizeof_ethernet
        and source = Macaddr.of_bytes_exn (copy_ethernet_src frame)
        and destination = Macaddr.of_bytes_exn (copy_ethernet_dst frame)
        in
        Ok ({ destination; source; ethertype;}, payload)
    else
      Error "frame too small to contain a valid ethernet header"
end

module Marshal = struct
  let unsafe_fill t buf =
    let open Ethernet_wire in
    set_ethernet_dst (Macaddr.to_bytes t.destination) 0 buf;
    set_ethernet_src (Macaddr.to_bytes t.source) 0 buf;
    set_ethernet_ethertype buf (ethertype_to_int t.ethertype);
    ()

  let into_cstruct t buf = unsafe_fill t buf

  let make_cstruct t =
    let buf = Cstruct.create Ethernet_wire.sizeof_ethernet in
    unsafe_fill t buf;
    buf
end
