/** Copyright 2009 Steve Jenson, released under Apache 2.0 License */
package com.saladwithsteve.namey.dns

import net.lag.extensions._
import net.lag.naggati._
import org.apache.mina.core.buffer.IoBuffer
import org.apache.mina.core.filterchain.IoFilter
import org.apache.mina.core.session.{DummySession, IoSession}
import org.apache.mina.filter.codec._
import org.specs._

object DnsCodecSpec extends Specification {
  private var fakeSession = new DummySession

  private val fakeDecoderOutput = new ProtocolDecoderOutput {
    override def flush(nextFilter: IoFilter.NextFilter, s: IoSession) = {}
    override def write(obj: AnyRef) = {
      written = obj :: written
    }
  }

  private var written: List[AnyRef] = Nil

  private var decoder = dns.Codec.decoder

  "dns" should {
    doBefore {
      fakeSession = new DummySession
      decoder = dns.Codec.decoder
      written = Nil
    }

    /* output according to tcpdump for an A query for hello.com
     0x0000:  0200 0000 4500 0037 7f10 0000 4011 0000  ....E..7....@...
     0x0010:  7f00 0001 7f00 0001 cd44 235d 0023 fe36  .........D#].#.6
     0x0020:  ed82 0100 0001 0000 0000 0000 0568 656c  .............hel
     0x0030:  6c6f 0363 6f6d 0000 0100 01              lo.com.....
    */

  "DNS" >> {
    "hello" >> {
      decoder.decode(fakeSession, IoBuffer.wrap(Array(0xed, 0x82, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01).map(_.toByte)), fakeDecoderOutput)
      written mustEqual Nil
    }
  }


    /*
    "HELO" >> {
      "throw an exception with a bare HELO" >> {
        decoder.decode(fakeSession, IoBuffer.wrap("HELO\n".getBytes), fakeDecoderOutput) must throwA[ProtocolError]
      }

      "accept a two-argument HELO" >> {
        decoder.decode(fakeSession, IoBuffer.wrap("HELO localhost\n".getBytes), fakeDecoderOutput)
        written mustEqual List(Request(List("HELO", "localhost"), None))
      }
    }

    "MAIL" >> {
      "Bare MAIL causes an error" >> {
          decoder.decode(fakeSession, IoBuffer.wrap("MAIL\n".getBytes), fakeDecoderOutput) must throwA[ProtocolError]
      }

      "MAIL FROM" >> {
        "MAIL FROM errors without a email address" >> {
          decoder.decode(fakeSession, IoBuffer.wrap("MAIL FROM:\n".getBytes), fakeDecoderOutput) must throwA[ProtocolError]
        }

        "MAIL FROM works with a close email address" >> {
          decoder.decode(fakeSession, IoBuffer.wrap("MAIL FROM:stevej@pobox.com\n".getBytes), fakeDecoderOutput)
          written mustEqual List(Request(List("MAIL", "FROM:", "stevej@pobox.com"), None))
        }

        "MAIL FROM works with an email address" >> {
          decoder.decode(fakeSession, IoBuffer.wrap("MAIL FROM: stevej@pobox.com\n".getBytes), fakeDecoderOutput)
          written mustEqual List(Request(List("MAIL", "FROM:", "stevej@pobox.com"), None))
        }

      }
    }

    "RCPT" >> {
      "RCPT TO:" >> {
        "RCPT TO: errors without an email address" >> {
          decoder.decode(fakeSession, IoBuffer.wrap("RCPT TO:\n".getBytes), fakeDecoderOutput) must throwA[ProtocolError]
        }

        "RCPT TO: works with an email address" >> {
          decoder.decode(fakeSession, IoBuffer.wrap("RCPT TO: stevej@pobox.com\n".getBytes), fakeDecoderOutput)
          written mustEqual List(Request(List("RCPT", "TO:", "stevej@pobox.com"), None))
        }
      }
    }

    "DATA" >> {
       "DATA requires a body" >> {
         decoder.decode(fakeSession, IoBuffer.wrap("DATA\n".getBytes), fakeDecoderOutput)
         written mustEqual List(Request(List("DATA"), None))
       }

      "A single header is accepted as an email body" >> {
        decoder.decode(fakeSession, IoBuffer.wrap("From: foo\nTo: bar\n\nthis is an email\r\n.\r\n".getBytes), fakeDecoderOutput)
        written(0) match {
          case Request(commands, Some(data)) => {
            commands mustEqual List("DATABODY")
            new String(data) mustEqual "From: foo\nTo: bar\n\nthis is an email\r\n.\r\n"
          }
          case _ => fail
        }
      }
    }

    "HELP responds" >> {
      decoder.decode(fakeSession, IoBuffer.wrap("HELP\n".getBytes), fakeDecoderOutput)
      written mustEqual List(Request(List("HELP"), None))
    }

    "VRFY responds" >> {
      decoder.decode(fakeSession, IoBuffer.wrap("VRFY <stevej@pobox.com>\n".getBytes), fakeDecoderOutput)
      written mustEqual List(Request(List("VRFY", "<stevej@pobox.com>"), None))
    }

    "NOOP" >> {
      "NOOP doesn't abide with your extra parameters" >> {
        decoder.decode(fakeSession, IoBuffer.wrap("NOOP fools\n".getBytes), fakeDecoderOutput) must throwA[ProtocolError]
      }

      "NOOP responds with 250" >> {
        decoder.decode(fakeSession, IoBuffer.wrap("NOOP\n".getBytes), fakeDecoderOutput)
        written mustEqual List(Request(List("NOOP"), None))
      }
    }

    "QUIT responds" >> {
      decoder.decode(fakeSession, IoBuffer.wrap("QUIT\n".getBytes), fakeDecoderOutput)
      written mustEqual List(Request(List("QUIT"), None))
    }

    "RSET responds" >> {
      decoder.decode(fakeSession, IoBuffer.wrap("RSET\n".getBytes), fakeDecoderOutput)
      written mustEqual List(Request(List("RSET"), None))
    }

    "HELP responds" >> {
      decoder.decode(fakeSession, IoBuffer.wrap("HELP\n".getBytes), fakeDecoderOutput)
      written mustEqual List(Request(List("HELP"), None))
    }

    "STATS requires passkey" >> {
      decoder.decode(fakeSession, IoBuffer.wrap("STATS\n".getBytes), fakeDecoderOutput) must throwA[ProtocolError]
    }

    "STATS passkey responds" >> {
      decoder.decode(fakeSession, IoBuffer.wrap("STATS foo\n".getBytes), fakeDecoderOutput)
      written mustEqual List(Request(List("STATS", "foo"), None))
    } */

  }
}
