type proto = [ `ARP | `IPv4 | `IPv6 ]

let pp_proto ppf = function
  | `ARP -> Fmt.string ppf "ARP"
  | `IPv4 -> Fmt.string ppf "IPv4"
  | `IPv6 -> Fmt.string ppf "IPv6"

type t = {
  source : Macaddr.t;
  destination : Macaddr.t;
  ethertype : proto;
}

let sizeof_ethernet = 14

let ethertype_to_int = function
  | `ARP -> 0x0806
  | `IPv4 -> 0x0800
  | `IPv6 -> 0x86dd

let int_to_ethertype = function
  | 0x0806 -> Some `ARP
  | 0x0800 -> Some `IPv4
  | 0x86dd -> Some `IPv6
  | _ -> None

type error = string

let pp fmt t =
  Format.fprintf fmt "%a -> %a: %a" Macaddr.pp t.source
    Macaddr.pp t.destination pp_proto t.ethertype

let equal {source; destination; ethertype} q =
  (Macaddr.compare source q.source) = 0 &&
  (Macaddr.compare destination q.destination) = 0 &&
  compare (ethertype_to_int ethertype) (ethertype_to_int q.ethertype) = 0

module Unmarshal = struct

  let of_cstruct frame =
    if Cstruct.length frame >= sizeof_ethernet then
      let raw_typ = Cstruct.BE.get_uint16 frame 12 in
      match raw_typ |> int_to_ethertype with
      | None -> Error (Printf.sprintf "unknown ethertype 0x%x in frame" raw_typ)
      | Some ethertype ->
        let payload = Cstruct.shift frame sizeof_ethernet
        and source = Macaddr.of_octets_exn (Cstruct.to_string ~off:6 ~len:6 frame)
        and destination = Macaddr.of_octets_exn (Cstruct.to_string ~off:0 ~len:6 frame)
        in
        Ok ({ destination; source; ethertype;}, payload)
    else
      Error "frame too small to contain a valid ethernet header"
end

module Marshal = struct
  let check_len buf =
    if sizeof_ethernet > Cstruct.length buf then
      Error "Not enough space for an Ethernet header"
    else Ok ()

  let unsafe_fill t buf =
    Cstruct.blit_from_string (Macaddr.to_octets t.destination) 0 buf 0 6;
    Cstruct.blit_from_string (Macaddr.to_octets t.source) 0 buf 6 6;
    Cstruct.BE.set_uint16 buf 12 (ethertype_to_int t.ethertype)

  let into_cstruct t buf =
    Result.map (fun () -> unsafe_fill t buf) (check_len buf)

  let make_cstruct t =
    let buf = Cstruct.create sizeof_ethernet in
    unsafe_fill t buf;
    buf
end
