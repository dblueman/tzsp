package tzsp

import (
   "errors"
   "net"

   "github.com/google/gopacket"
   "github.com/google/gopacket/layers"
   "github.com/google/gopacket/pcap"
)

type Decoder struct {
   packetSource *gopacket.PacketSource
   handle *pcap.Handle
   conn *net.UDPConn
}

func NewFromNetwork() (*Decoder, error) {
   conn, err := net.ListenUDP("udp", &net.UDPAddr{
      Port: 37008,
      IP: net.ParseIP("0.0.0.0"),
   })
   if err != nil {
      return nil, err
   }

   return &Decoder{conn: conn}, nil
}

func NewFromFile(fname string) (*Decoder, error) {
   handle, err := pcap.OpenOffline(fname)
   if err != nil {
      return nil, err
   }

   packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
   return &Decoder{packetSource: packetSource, handle: handle}, nil
}

func (tzsp *Decoder) Next() (*Frame, error) {
   var rlen int
   var err error
   var msg []byte

   if tzsp.conn != nil {
      msg2 := make([]byte, 1600)
      rlen, _, err = tzsp.conn.ReadFromUDP(msg2)
      if err != nil {
         return nil, err
      }

      msg = msg2[:rlen]
   } else {
      packet, err := tzsp.packetSource.NextPacket()
      if err != nil {
         return nil, err
      }

      udpLayer := packet.Layer(layers.LayerTypeUDP)
      if udpLayer == nil {
         return nil, errors.New("packet has no UDP layer (fragment?)")
      }

      udp := udpLayer.(*layers.UDP)

      if udp.DstPort != 37008 {
         return nil, errors.New("not TZSP packet")
      }

      app := packet.ApplicationLayer()
      if app == nil {
         return nil, errors.New("decode failure (application layer)")
      }

      errL := packet.ErrorLayer()
      if errL != nil {
         return nil, errors.New("decode failure (error layer)")
      }

      msg = app.Payload()
   }

   frame := Frame{}
   offset, err := frame.DecodeTZSP(msg)
   if err != nil {
      return nil, err
   }

   frame.DecodeIEEE80211(msg[offset:])
   return &frame, nil
}
