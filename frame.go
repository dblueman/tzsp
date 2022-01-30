package tzsp

import (
   "errors"
   "fmt"
   "sort"
   "strconv"
   "unsafe"
)

type FrameIEEE80211 struct {
   Control     uint16
   Duration    uint16
   Receiver    [6]uint8
   Transmitter [6]uint8
   Source      [6]uint8
}

type FrameTZSP struct {
   Version       uint8
   Type          uint8
   Encapsulation uint16
   Tag           uint8
}

const (
   TZSPTypeReceived   = 0
   TZSPEncap80211     = 18 << 8
   TZSPTagSignal      = 10
   TZSPTagRate        = 12
   TZSPTagFCS         = 17
   TZSPTagChannel     = 18
   TZSPTagOrigLen     = 41
   TZSPTagSensorMAC   = 60
   TZSPTagEnd         = 1
   i8TagSSID          = 0
)

type TZSPTag struct {
   TZSPTag uint8
   Len uint8
   Val [6]uint8
}

type Frame map[string]interface{}

func (f *Frame) Print() {
   var keys []string

   // sort keys
   for k := range *f {
      keys = append(keys, k)
   }
   sort.Strings(keys)

   for _, k := range keys {
      v := (*f)[k]
      fmt.Printf("%12s ", k)

      octets, ok := v.([]uint8)
      if ok {
         for i, octet := range octets {
            if i > 0 {
               fmt.Print(":")
            }
            fmt.Printf("%02X", octet)
         }
         fmt.Println()
      } else {
         fmt.Printf("%v\n", v)
      }
   }

   fmt.Println()
}

func (f *Frame) DecodeTZSP(buf []byte) (int, error) {
   tzsp := (*FrameTZSP)(unsafe.Pointer(&buf[0]))

   if tzsp.Version != 1 || tzsp.Type != TZSPTypeReceived || tzsp.Encapsulation != TZSPEncap80211 {
      return -1, errors.New("malformed TZSP frame")
   }

   TZSPTagp := (*TZSPTag)(unsafe.Pointer(&tzsp.Tag))

   for {
      if TZSPTagp.Len == 0 {
         return -1, errors.New("zero length tag")
      }

      switch TZSPTagp.TZSPTag {
      case TZSPTagSignal:
         (*f)["signal"] = int8(TZSPTagp.Val[0])
      case TZSPTagRate:
         (*f)["rate"] = TZSPTagp.Val[0]
      case TZSPTagFCS:
         (*f)["FCS"] = TZSPTagp.Val[0] == 0
      case TZSPTagChannel:
         (*f)["channel"] = TZSPTagp.Val[0]
      case TZSPTagOrigLen:
         (*f)["origLen"] = uint16(TZSPTagp.Val[1]) | (uint16(TZSPTagp.Val[0]) << 8)
      case TZSPTagSensorMAC:
         (*f)["sensor"] = TZSPTagp.Val
      case TZSPTagEnd:
         // return offset of next frame
         offset := int(uintptr(unsafe.Pointer(TZSPTagp)) - uintptr(unsafe.Pointer(&buf[0])) + 1)
//         fmt.Printf("frame %+v offset=%v\n", f, offset)
         return offset, nil
      default:
         return -1, errors.New("unknown TZSP TZSPTag "+strconv.Itoa(int(TZSPTagp.TZSPTag)))
      }

      // move to next TZSPTag
      TZSPTagp = (*TZSPTag)(unsafe.Pointer((uintptr(unsafe.Pointer(TZSPTagp)) + 2 + uintptr(TZSPTagp.Len))))
   }
}

func (f *Frame) DecodeIEEE80211(buf []byte) {
/*fmt.Print("IEEE802.11:")
for _, a := range buf {
   fmt.Printf(" %02x", a)
}
fmt.Println()
*/
/*   if len(buf) < 36 {
      return
   }*/

   version := buf[0] & 3
   xtype := (buf[0] >> 2) & 3
   subtype := buf[0] >> 4

   // see 802.11-2012 p382
   (*f)["version"] = version
   (*f)["type"] = xtype
   (*f)["subtype"] = subtype
   (*f)["toDS"] = buf[1] & 1
   (*f)["fromDS"] = (buf[1] >> 1) & 1
   (*f)["moreFrag"] = (buf[1] >> 2) & 1
   (*f)["retry"] = (buf[1] >> 3) & 1
   (*f)["pwrmgt"] = (buf[1] >> 4) & 1
   (*f)["moreData"] = (buf[1] >> 5) & 1
   (*f)["WEP"] = (buf[1] >> 6) & 1
   (*f)["order"] = (buf[1] >> 7) & 1
   (*f)["duration"] = uint16(buf[2]) | (uint16(buf[3]) << 8)
   (*f)["receiver"] = buf[4:10]

   // beacon frame
   if version == 0 && xtype == 0 && subtype == 8 {
      (*f)["transmitter"] = buf[10:16]
      (*f)["BSS"] = buf[16:22]
      (*f)["fragment"] = buf[34] & 0xf
      (*f)["sequence"] = (uint16(buf[22]) >> 4) | (uint16(buf[23]) << 4)

/*      b := bytes.NewBuffer(buf)
      var timestamp uint64
      binary.Read(b[24:], binary.LittleEndian, timestamp)

      (*f)["timestamp"] = timestamp */
      (*f)["interval"] = uint16(buf[32]) | (uint16(buf[33]) << 8)
      (*f)["capabilities"] = uint16(buf[34]) | (uint16(buf[35]) << 8)

      offset := 36

      switch buf[offset] {
      case 0: // SSID
         length := int(buf[offset+1])
         (*f)["SSID"] = string(buf[offset+2:offset+2+length])
      }
   }
}
